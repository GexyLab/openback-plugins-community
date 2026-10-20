using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using OpenBack.AppAuth.Internal;

namespace OpenBack.AppAuth
{
    /// <summary>
    /// The client of an OpenBack user pool for .NET apps (desktop, MAUI, Xamarin, Unity, console) and for server-side
    /// "backend" calls. Two ways to sign users in, freely mixed:
    /// <list type="bullet">
    /// <item>your own forms: <see cref="SignUpAsync"/>, <see cref="SignInWithPasswordAsync"/>, <see cref="SignInWithEmailCodeAsync"/>,
    /// <see cref="SignInAnonymouslyAsync"/>, <see cref="VerifyMfaAsync"/> call the pool's JSON API (<c>&lt;issuer&gt;/api/v1</c>);</item>
    /// <item>the pool's hosted sign-in page (OpenID Connect, code + PKCE): <see cref="SignInWithSystemBrowserAsync"/> (desktop,
    /// loopback redirect) or <see cref="BuildAuthorizationRequestAsync"/> + <see cref="HandleRedirectCallbackAsync"/>.</item>
    /// </list>
    /// The session is kept in an <see cref="ITokenStorage"/>; the access token is renewed before it expires, one refresh at a
    /// time (the refresh token rotates at every use); <see cref="AuthStateChanged"/> tells the app when the user changes.
    /// Thread-safe. One instance per app (per pool + client ID).
    /// </summary>
    public sealed class AppAuthClient : IDisposable
    {
        private const string Api = "/api/v1";
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;
        private readonly ITokenStorage _storage;
        private readonly string? _redirectUri;
        private readonly string? _clientSecret;
        private readonly TimeSpan _skew;
        private readonly Func<DateTimeOffset> _clock;
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);
        private readonly SemaphoreSlim _stateLock = new SemaphoreSlim(1, 1);
        private readonly SemaphoreSlim _loadLock = new SemaphoreSlim(1, 1);
        private volatile StoredSession? _state;
        private volatile bool _loaded;

        /// <param name="issuer">The pool's address, e.g. <c>https://api.example.com/gateway/shop/auth/main</c>.</param>
        /// <param name="clientId">The app's client ID (<c>uapp_...</c>) from the pool's Apps tab.</param>
        /// <param name="options">Redirect URI, storage, HTTP client...</param>
        public AppAuthClient(string issuer, string clientId, AppAuthClientOptions? options = null)
        {
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentException("The client ID is required.", nameof(clientId));
            options = options ?? new AppAuthClientOptions();
            Issuer = Internal.Issuer.Normalize(issuer);
            ClientId = clientId.Trim();
            StorageKey = string.IsNullOrEmpty(options.StorageKey) ? "openback.auth." + ClientId : options.StorageKey!;
            _storage = options.Storage ?? new InMemoryTokenStorage();
            _http = options.HttpClient ?? new HttpClient();
            _ownsHttp = options.HttpClient == null;
            _redirectUri = options.RedirectUri;
            _clientSecret = options.ClientSecret;
            _skew = options.RefreshSkew;
            _clock = options.Clock ?? (() => DateTimeOffset.UtcNow);
        }

        /// <summary>Makes a client and restores the stored session (<see cref="InitializeAsync"/>).</summary>
        public static async Task<AppAuthClient> CreateAsync(string issuer, string clientId, AppAuthClientOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            var client = new AppAuthClient(issuer, clientId, options);
            await client.InitializeAsync(cancellationToken).ConfigureAwait(false);
            return client;
        }

        public string Issuer { get; }
        public string ClientId { get; }
        /// <summary>The storage key of the session (<c>openback.auth.&lt;clientId&gt;</c> by default).</summary>
        public string StorageKey { get; }

        /// <summary>The signed-in user (null when signed out, or before <see cref="InitializeAsync"/> restored the session).</summary>
        public PoolUser? CurrentUser => _state?.User;

        /// <summary>The active organization (B2B pools).</summary>
        public ActiveOrg? CurrentOrg => _state?.Org;

        /// <summary>True while a session is kept.</summary>
        public bool IsSignedIn => _state?.AccessToken != null;

        /// <summary>The claims of the current access token, decoded WITHOUT verification (display only).</summary>
        public JsonElement? AccessTokenClaims => Jwt.DecodePayload(_state?.AccessToken);

        /// <summary>Raised when the user signs in, out, or changes (profile, organization). Handlers' exceptions are ignored.
        /// May be raised on any thread: marshal to the UI thread yourself.</summary>
        public event EventHandler<AuthStateChangedEventArgs>? AuthStateChanged;

        /// <summary>Calls <paramref name="listener"/> now with the current state and at every change; dispose the result to stop.</summary>
        public IDisposable OnAuthStateChanged(Action<PoolUser?, ActiveOrg?> listener)
        {
            if (listener == null) throw new ArgumentNullException(nameof(listener));
            EventHandler<AuthStateChangedEventArgs> handler = (sender, e) => listener(e.User, e.Org);
            AuthStateChanged += handler;
            var s = _state;
            try { listener(s?.User, s?.Org); } catch { /* a listener's error is its own */ }
            return new Unsubscriber(() => AuthStateChanged -= handler);
        }

        /// <summary>Restores the stored session (every async method does it on first use).</summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            if (_loaded) return;
            await _loadLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_loaded) return;
                var stored = await ReadStoredAsync(cancellationToken).ConfigureAwait(false);
                _loaded = true;
                if (stored != null)
                {
                    _state = stored;
                    Notify();
                }
            }
            finally
            {
                _loadLock.Release();
            }
        }

        // ------------------------------------------------------------------------------------------------ configuration

        /// <summary>The pool's public configuration: sign-in methods, providers, password policy, branding.</summary>
        public async Task<PoolConfig> GetConfigAsync(CancellationToken cancellationToken = default)
        {
            var data = await CallAsync(HttpMethod.Get, "/config", null, false, cancellationToken).ConfigureAwait(false);
            return Json.To<PoolConfig>(data) ?? new PoolConfig();
        }

        // ------------------------------------------------------------------------------------------------------ tokens

        /// <summary>An access token for your API calls: the stored one if it expires in more than a minute, else a renewed one.</summary>
        /// <exception cref="AppAuthException"><c>not_signed_in</c>, <c>invalid_refresh_token</c> (session ended: signed out),
        /// <c>network_error</c> (the session is kept; try again later).</exception>
        public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            await InitializeAsync(cancellationToken).ConfigureAwait(false);
            var s = _state;
            if (s?.AccessToken != null && IsFresh(s)) return s.AccessToken!;
            return await RefreshCoreAsync(null, s?.RefreshToken, onlyIfStale: true, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Renews the tokens now (optionally into another organization). One refresh at a time: concurrent callers
        /// share the result. The request is never retried automatically, and once sent it is not cancelled (the refresh
        /// token rotates: losing the answer would end the session).</summary>
        public async Task<string> RefreshAsync(string? orgId = null, CancellationToken cancellationToken = default)
        {
            await InitializeAsync(cancellationToken).ConfigureAwait(false);
            return await RefreshCoreAsync(orgId, _state?.RefreshToken, onlyIfStale: false, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>An <see cref="HttpClient"/> that adds <c>Authorization: Bearer &lt;access token&gt;</c> to every request
        /// (for YOUR API, e.g. behind the OpenBack gateway).</summary>
        public HttpClient CreateAuthorizedHttpClient(HttpMessageHandler? innerHandler = null)
        {
            return new HttpClient(new AppAuthHttpHandler(this, innerHandler ?? new HttpClientHandler()));
        }

        // ------------------------------------------------------------------------------------------ sign-up and sign-in

        public async Task<AuthOutcome> SignUpAsync(string email, string password, string? displayName = null, string? locale = null,
            string? orgId = null, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("email", email), ("password", password), ("display_name", displayName ?? ""), ("locale", locale), ("org_id", orgId));
            return await OutcomeAsync(await CallAsync(HttpMethod.Post, "/signup", body, false, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        public async Task<AuthOutcome> SignInWithPasswordAsync(string email, string password, string? orgId = null,
            CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("email", email), ("password", password), ("org_id", orgId));
            return await OutcomeAsync(await CallAsync(HttpMethod.Post, "/signin/password", body, false, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        /// <summary>Sends a sign-in code (and link) by email. Always answers <c>sent</c> (no account enumeration).</summary>
        public async Task<StatusResult> SendEmailCodeAsync(string email, CancellationToken cancellationToken = default)
        {
            return Status(await CallAsync(HttpMethod.Post, "/signin/email-code", Json.Body(("email", email)), false, cancellationToken).ConfigureAwait(false));
        }

        public async Task<AuthOutcome> SignInWithEmailCodeAsync(string email, string code, string? orgId = null,
            CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("email", email), ("code", code), ("org_id", orgId));
            return await OutcomeAsync(await CallAsync(HttpMethod.Post, "/signin/email-code/verify", body, false, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        /// <summary>Signs in with the token of an email sign-in link.</summary>
        public async Task<AuthOutcome> SignInWithEmailLinkTokenAsync(string token, string? orgId = null, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("token", token), ("org_id", orgId));
            return await OutcomeAsync(await CallAsync(HttpMethod.Post, "/signin/email-code/verify", body, false, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        /// <summary>A guest account (when the pool allows it); upgrade it later with <see cref="UpgradeAnonymousAsync"/>.</summary>
        public async Task<AuthOutcome> SignInAnonymouslyAsync(CancellationToken cancellationToken = default)
        {
            return await OutcomeAsync(await CallAsync(HttpMethod.Post, "/signin/anonymous", null, false, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        /// <summary>The second step of a sign-in (<see cref="AuthStatus.MfaRequired"/>): a TOTP code or a recovery code.</summary>
        public async Task<AuthOutcome> VerifyMfaAsync(string mfaToken, string code, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("mfa_token", mfaToken), ("code", code));
            return await OutcomeAsync(await CallAsync(HttpMethod.Post, "/signin/mfa", body, false, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        /// <summary>Starts enrolling an authenticator app: with the <paramref name="mfaToken"/> of a
        /// <see cref="AuthStatus.MfaEnrollRequired"/> outcome, or signed in (null).</summary>
        public async Task<MfaEnrollment> EnrollMfaAsync(string? mfaToken = null, CancellationToken cancellationToken = default)
        {
            var data = mfaToken != null
                ? await CallAsync(HttpMethod.Post, "/mfa/enroll", Json.Body(("mfa_token", mfaToken)), false, cancellationToken).ConfigureAwait(false)
                : await CallAsync(HttpMethod.Post, "/mfa/enroll", Json.Body(), true, cancellationToken).ConfigureAwait(false);
            return Json.To<MfaEnrollment>(data) ?? new MfaEnrollment();
        }

        /// <summary>Confirms the enrollment with a first code. Returns the recovery codes (show them once) and, with an
        /// <paramref name="mfaToken"/>, the sign-in outcome (the session is kept when it is Ok).</summary>
        public async Task<MfaConfirmation> ConfirmMfaAsync(string code, string? mfaToken = null, CancellationToken cancellationToken = default)
        {
            if (mfaToken != null)
            {
                var data = await CallAsync(HttpMethod.Post, "/mfa/enroll/confirm", Json.Body(("mfa_token", mfaToken), ("code", code)), false, cancellationToken).ConfigureAwait(false);
                var outcome = await OutcomeAsync(data).ConfigureAwait(false);
                return new MfaConfirmation { RecoveryCodes = Json.StrList(data, "recovery_codes"), Outcome = outcome };
            }
            var signedIn = await CallAsync(HttpMethod.Post, "/mfa/enroll/confirm", Json.Body(("code", code)), true, cancellationToken).ConfigureAwait(false);
            return new MfaConfirmation { RecoveryCodes = Json.StrList(signedIn, "recovery_codes") };
        }

        /// <summary>Turns two-step verification off (signed in; a current code is required).</summary>
        public async Task<StatusResult> DisableMfaAsync(string code, CancellationToken cancellationToken = default)
        {
            return Status(await CallAsync(HttpMethod.Post, "/mfa/disable", Json.Body(("code", code)), true, cancellationToken).ConfigureAwait(false));
        }

        // ----------------------------------------------------------------------------------------- passwords and emails

        /// <summary>Sends a password reset email. Always answers <c>sent</c>.</summary>
        public async Task<StatusResult> SendPasswordResetAsync(string email, CancellationToken cancellationToken = default)
        {
            return Status(await CallAsync(HttpMethod.Post, "/password/forgot", Json.Body(("email", email)), false, cancellationToken).ConfigureAwait(false));
        }

        /// <summary>Sets a new password with the token of a reset link.</summary>
        public async Task<StatusResult> ResetPasswordWithTokenAsync(string token, string newPassword, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("token", token), ("new_password", newPassword));
            return Status(await CallAsync(HttpMethod.Post, "/password/reset", body, false, cancellationToken).ConfigureAwait(false));
        }

        /// <summary>Sets a new password with the code of a reset email.</summary>
        public async Task<StatusResult> ResetPasswordWithCodeAsync(string email, string code, string newPassword, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("email", email), ("code", code), ("new_password", newPassword));
            return Status(await CallAsync(HttpMethod.Post, "/password/reset", body, false, cancellationToken).ConfigureAwait(false));
        }

        /// <summary>Sets the new password asked by a <see cref="AuthStatus.PasswordChangeRequired"/> outcome; then sign in again.</summary>
        public async Task<StatusResult> ChangeForcedPasswordAsync(string changeToken, string newPassword, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("change_token", changeToken), ("new_password", newPassword));
            return Status(await CallAsync(HttpMethod.Post, "/password/reset", body, false, cancellationToken).ConfigureAwait(false));
        }

        /// <summary>Verifies the email address with the token of a verification link.</summary>
        public async Task<StatusResult> VerifyEmailWithTokenAsync(string token, CancellationToken cancellationToken = default)
        {
            return await UserStatusAsync(await CallAsync(HttpMethod.Post, "/email/verify", Json.Body(("token", token)), false, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        /// <summary>Verifies the email address with the code of a verification email.</summary>
        public async Task<StatusResult> VerifyEmailWithCodeAsync(string email, string code, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("email", email), ("code", code));
            return await UserStatusAsync(await CallAsync(HttpMethod.Post, "/email/verify", body, false, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        /// <summary>Sends the verification email again (signed in).</summary>
        public async Task<StatusResult> ResendVerificationAsync(CancellationToken cancellationToken = default)
        {
            return Status(await CallAsync(HttpMethod.Post, "/email/verify/send", Json.Body(), true, cancellationToken).ConfigureAwait(false));
        }

        // ----------------------------------------------------------------------------------------------- the signed-in user

        /// <summary>The signed-in user, fresh from the pool (with organization, roles, linked providers).</summary>
        public async Task<PoolUser> MeAsync(CancellationToken cancellationToken = default)
        {
            var user = Json.To<PoolUser>(await CallAsync(HttpMethod.Get, "/me", null, true, cancellationToken).ConfigureAwait(false)) ?? new PoolUser();
            await UpdateStateAsync(s => s?.WithUser(user), notify: false).ConfigureAwait(false);
            return user;
        }

        public async Task<PoolUser> UpdateProfileAsync(ProfileUpdate update, CancellationToken cancellationToken = default)
        {
            if (update == null) throw new ArgumentNullException(nameof(update));
            var body = Json.Body(("display_name", update.DisplayName), ("photo_url", update.PhotoUrl), ("locale", update.Locale));
            var user = Json.To<PoolUser>(await CallAsync(new HttpMethod("PATCH"), "/me", body, true, cancellationToken).ConfigureAwait(false)) ?? new PoolUser();
            await UpdateStateAsync(s => s?.WithUser(user), notify: true).ConfigureAwait(false);
            return user;
        }

        /// <summary>Changes the password. Every session of the user ends: the local one is cleared (sign in again).</summary>
        public async Task<StatusResult> ChangePasswordAsync(string? currentPassword, string newPassword, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("current_password", currentPassword), ("new_password", newPassword));
            var result = Status(await CallAsync(HttpMethod.Post, "/me/password", body, true, cancellationToken).ConfigureAwait(false));
            await ClearAsync().ConfigureAwait(false);
            return result;
        }

        /// <summary>Starts an email change: a code is sent to the new address (<see cref="ConfirmEmailChangeWithCodeAsync"/>).</summary>
        public async Task<StatusResult> ChangeEmailAsync(string newEmail, CancellationToken cancellationToken = default)
        {
            return Status(await CallAsync(HttpMethod.Post, "/me/email", Json.Body(("new_email", newEmail)), true, cancellationToken).ConfigureAwait(false));
        }

        public async Task<StatusResult> ConfirmEmailChangeWithCodeAsync(string code, CancellationToken cancellationToken = default)
        {
            return await UserStatusAsync(await CallAsync(HttpMethod.Post, "/me/email/confirm", Json.Body(("code", code)), true, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        public async Task<StatusResult> ConfirmEmailChangeWithTokenAsync(string token, CancellationToken cancellationToken = default)
        {
            return await UserStatusAsync(await CallAsync(HttpMethod.Post, "/me/email/confirm", Json.Body(("token", token)), true, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        /// <summary>Turns a guest account into a real one (same user id).</summary>
        public async Task<StatusResult> UpgradeAnonymousAsync(string email, string password, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("email", email), ("password", password));
            return await UserStatusAsync(await CallAsync(HttpMethod.Post, "/me/upgrade", body, true, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        /// <summary>Deletes the account (the password is required when the account has one); the session is cleared.</summary>
        public async Task<StatusResult> DeleteAccountAsync(string? password = null, CancellationToken cancellationToken = default)
        {
            var result = Status(await CallAsync(HttpMethod.Delete, "/me", Json.Body(("password", password)), true, cancellationToken).ConfigureAwait(false));
            await ClearAsync().ConfigureAwait(false);
            return result;
        }

        /// <summary>Signs out: tells the pool (best effort: revokes the refresh token, or every session with
        /// <paramref name="everywhere"/>) and always clears the local session.</summary>
        public async Task SignOutAsync(bool everywhere = false, CancellationToken cancellationToken = default)
        {
            await InitializeAsync(cancellationToken).ConfigureAwait(false);
            var s = _state;
            if (s?.AccessToken != null || s?.RefreshToken != null)
            {
                try
                {
                    // The access token is sent only while valid (no refresh just to sign out).
                    var bearer = s!.AccessToken != null && s.ExpiresAt > _clock().ToUnixTimeMilliseconds() ? s.AccessToken : null;
                    var body = Json.Body(("refresh_token", s.RefreshToken), ("everywhere", everywhere));
                    await SendApiAsync(HttpMethod.Post, "/signout", body, bearer, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    await ClearAsync().ConfigureAwait(false);
                    throw;
                }
                catch (Exception)
                {
                    // Signed out locally anyway.
                }
            }
            await ClearAsync().ConfigureAwait(false);
        }

        // -------------------------------------------------------------------------------------- organizations (B2B pools)

        /// <summary>The user's organizations (B2C pools: always empty).</summary>
        public async Task<OrganizationList> GetOrganizationsAsync(CancellationToken cancellationToken = default)
        {
            return Json.To<OrganizationList>(await CallAsync(HttpMethod.Get, "/orgs", null, true, cancellationToken).ConfigureAwait(false)) ?? new OrganizationList();
        }

        /// <summary>A new organization, the user its owner (when the pool allows self-service creation).</summary>
        public async Task<OrganizationMembership> CreateOrganizationAsync(string name, CancellationToken cancellationToken = default)
        {
            return Json.To<OrganizationMembership>(await CallAsync(HttpMethod.Post, "/orgs", Json.Body(("name", name)), true, cancellationToken).ConfigureAwait(false))
                   ?? new OrganizationMembership();
        }

        /// <summary>Signs in to another organization of the user (new tokens). Returns the new active organization.</summary>
        public async Task<ActiveOrg?> SwitchOrganizationAsync(string orgId, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(orgId)) throw new ArgumentException("orgId is required", nameof(orgId));
            await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
            await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var current = _state;
                if (current?.RefreshToken == null || current.AccessToken == null) throw NotSignedIn();
                var body = Json.Body(("org_id", orgId), ("refresh_token", current.RefreshToken));
                JsonElement data;
                try
                {
                    // Not cancellable once sent: the refresh token rotates.
                    data = await SendApiAsync(HttpMethod.Post, "/orgs/switch", body, current.AccessToken, CancellationToken.None).ConfigureAwait(false);
                }
                catch (AppAuthException e) when (e.IsSessionEnded || e.Code == "not_a_member")
                {
                    // not_a_member: the pool has already consumed the refresh token, the session cannot be renewed.
                    await ClearAsync().ConfigureAwait(false);
                    throw;
                }
                var next = SessionFrom(data, current.User, current.IdToken);
                await WriteStateAsync(next, notify: true).ConfigureAwait(false);
                return next.Org;
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        /// <summary>The members of an organization (owners and admins only).</summary>
        public async Task<OrgMemberPage> GetMembersAsync(string orgId, string? query = null, int skip = 0, int limit = 50,
            CancellationToken cancellationToken = default)
        {
            var qs = Query.Build(new[]
            {
                new KeyValuePair<string, string?>("q", query ?? ""),
                new KeyValuePair<string, string?>("skip", skip.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string?>("limit", limit.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            });
            var data = await CallAsync(HttpMethod.Get, "/orgs/" + Uri.EscapeDataString(orgId) + "/members?" + qs, null, true, cancellationToken).ConfigureAwait(false);
            return Json.To<OrgMemberPage>(data) ?? new OrgMemberPage();
        }

        /// <summary>Adds a member: an existing user of the pool, or a new account (see <see cref="AddedMember.TemporaryPassword"/>).</summary>
        public async Task<AddedMember> AddMemberAsync(string orgId, string email, string? displayName = null, string? password = null,
            IEnumerable<string>? roles = null, CancellationToken cancellationToken = default)
        {
            var body = Json.Body(("email", email), ("display_name", displayName ?? ""), ("password", password), ("roles", new List<string>(roles ?? Array.Empty<string>())));
            var data = await CallAsync(HttpMethod.Post, "/orgs/" + Uri.EscapeDataString(orgId) + "/members", body, true, cancellationToken).ConfigureAwait(false);
            return Json.To<AddedMember>(data) ?? new AddedMember();
        }

        public async Task<MemberRoles> SetMemberRolesAsync(string orgId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default)
        {
            var path = "/orgs/" + Uri.EscapeDataString(orgId) + "/members/" + Uri.EscapeDataString(userId);
            var data = await CallAsync(new HttpMethod("PATCH"), path, Json.Body(("roles", new List<string>(roles ?? Array.Empty<string>()))), true, cancellationToken).ConfigureAwait(false);
            return Json.To<MemberRoles>(data) ?? new MemberRoles();
        }

        public async Task<StatusResult> RemoveMemberAsync(string orgId, string userId, CancellationToken cancellationToken = default)
        {
            var path = "/orgs/" + Uri.EscapeDataString(orgId) + "/members/" + Uri.EscapeDataString(userId);
            return Status(await CallAsync(HttpMethod.Delete, path, null, true, cancellationToken).ConfigureAwait(false));
        }

        // ------------------------------------------------------------------------------------- hosted sign-in (OIDC)

        /// <summary>Prepares a hosted sign-in (authorization code + PKCE S256): the URL to open and the transaction, which is
        /// also saved in the storage (<c>&lt;key&gt;.pkce</c>) for <see cref="HandleRedirectCallbackAsync"/>.</summary>
        public async Task<AuthorizationRequest> BuildAuthorizationRequestAsync(AuthorizationRequestOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            var redirect = options?.RedirectUri ?? _redirectUri;
            if (string.IsNullOrEmpty(redirect))
                throw new InvalidOperationException("A redirect URI is required: set AppAuthClientOptions.RedirectUri.");
            var tx = OidcProtocol.NewTransaction(redirect!, _clock());
            await _storage.SetAsync(StorageKey + ".pkce", tx.ToJson(), cancellationToken).ConfigureAwait(false);
            return new AuthorizationRequest(OidcProtocol.AuthorizeUrl(Issuer, ClientId, tx, options), tx);
        }

        /// <summary>Completes a hosted sign-in from the URL the browser came back to: checks <c>error</c>, <c>state</c>
        /// (constant time) and <c>iss</c>, exchanges the code (with the PKCE verifier), checks the ID token's
        /// <c>nonce</c>, keeps the session and returns the user. Returns null when the URL carries no code nor error.</summary>
        public async Task<PoolUser?> HandleRedirectCallbackAsync(string callbackUrl, CancellationToken cancellationToken = default)
        {
            await InitializeAsync(cancellationToken).ConfigureAwait(false);
            var query = Query.Parse(callbackUrl ?? "");
            if (!query.ContainsKey("code") && !query.ContainsKey("error")) return null;
            OidcTransaction? tx = null;
            var pending = await _storage.GetAsync(StorageKey + ".pkce", cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(pending))
            {
                try { tx = OidcTransaction.FromJson(pending!); } catch (Exception e) when (e is FormatException || e is JsonException) { tx = null; }
            }
            var code = OidcProtocol.CheckCallback(query, tx, Issuer);
            await _storage.RemoveAsync(StorageKey + ".pkce", cancellationToken).ConfigureAwait(false);

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = tx!.RedirectUri,
                ["client_id"] = ClientId,
                ["code_verifier"] = tx.CodeVerifier,
            };
            var data = await TokenEndpointAsync(form, cancellationToken).ConfigureAwait(false);
            var idToken = Json.Str(data, "id_token");
            if (idToken != null) OidcProtocol.CheckIdTokenUnverified(idToken, Issuer, ClientId, tx.Nonce);
            await WriteStateAsync(SessionFrom(data, null, null), notify: false).ConfigureAwait(false);
            PoolUser? user = null;
            try
            {
                user = await MeAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (AppAuthException)
            {
                // Signed in; the profile can be read later.
            }
            Notify();
            return user;
        }

        /// <summary>
        /// Desktop sign-in through the system browser (WPF, WinForms, console, Avalonia...): listens on the registered
        /// loopback redirect URI (<c>http://127.0.0.1:&lt;port&gt;/&lt;path&gt;</c>, HttpListener), opens the hosted page in
        /// the default browser, waits for the redirect and completes the sign-in. Register the exact loopback URI in the
        /// pool's Apps tab (kind <c>native</c>).
        /// </summary>
        public async Task<PoolUser?> SignInWithSystemBrowserAsync(SystemBrowserOptions? browser = null, AuthorizationRequestOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            browser = browser ?? new SystemBrowserOptions();
            var redirect = browser.RedirectUri ?? options?.RedirectUri ?? _redirectUri;
            if (string.IsNullOrEmpty(redirect))
                throw new InvalidOperationException("A loopback redirect URI is required (e.g. http://127.0.0.1:53682/callback).");
            var authorize = CopyWithRedirect(options, redirect!);
            return await LoopbackSignIn.RunAsync(this, redirect!, browser, authorize, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>The hosted sign-out URL (ends the pool's browser session): <c>&lt;issuer&gt;/logout?client_id=..&amp;id_token_hint=..</c>.
        /// <paramref name="postLogoutRedirectUri"/> must be registered in the app's post-logout redirect URIs.</summary>
        public Uri BuildLogoutUrl(string? postLogoutRedirectUri = null, string? state = null)
        {
            var p = new List<KeyValuePair<string, string?>>
            {
                new KeyValuePair<string, string?>("client_id", ClientId),
                new KeyValuePair<string, string?>("id_token_hint", _state?.IdToken),
                new KeyValuePair<string, string?>("post_logout_redirect_uri", postLogoutRedirectUri),
                new KeyValuePair<string, string?>("state", state),
            };
            return new Uri(Issuer + "/logout?" + Query.Build(p));
        }

        /// <summary>Desktop sign-out: signs out (<see cref="SignOutAsync"/>) and opens the hosted sign-out page in the system
        /// browser, which also ends the pool's browser session.</summary>
        public async Task SignOutWithSystemBrowserAsync(string? postLogoutRedirectUri = null, Func<Uri, Task>? openBrowser = null,
            CancellationToken cancellationToken = default)
        {
            await InitializeAsync(cancellationToken).ConfigureAwait(false);
            var url = BuildLogoutUrl(postLogoutRedirectUri);
            await SignOutAsync(false, cancellationToken).ConfigureAwait(false);
            await (openBrowser ?? LoopbackSignIn.OpenSystemBrowser)(url).ConfigureAwait(false);
        }

        public void Dispose()
        {
            if (_ownsHttp) _http.Dispose();
        }

        // ------------------------------------------------------------------------------------------------- internals

        private static AuthorizationRequestOptions CopyWithRedirect(AuthorizationRequestOptions? o, string redirect)
        {
            o = o ?? new AuthorizationRequestOptions();
            return new AuthorizationRequestOptions
            {
                Provider = o.Provider, OrgId = o.OrgId, Prompt = o.Prompt, ScreenHint = o.ScreenHint, LoginHint = o.LoginHint,
                MaxAge = o.MaxAge, Scope = o.Scope, UiLocales = o.UiLocales, RedirectUri = redirect,
            };
        }

        private bool IsFresh(StoredSession s)
        {
            return s.AccessToken != null && s.ExpiresAt - _clock().ToUnixTimeMilliseconds() > (long)_skew.TotalMilliseconds;
        }

        private static AppAuthException NotSignedIn() => new AppAuthException(401, "not_signed_in", "Not signed in.");

        private async Task<string> RefreshCoreAsync(string? orgId, string? observedRefreshToken, bool onlyIfStale, CancellationToken ct)
        {
            if (_state?.RefreshToken == null) throw NotSignedIn();
            await _refreshLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var current = _state;
                if (current?.RefreshToken == null) throw NotSignedIn();
                if (orgId == null)
                {
                    // Another caller renewed while this one waited: share its result.
                    if (onlyIfStale && IsFresh(current)) return current.AccessToken!;
                    if (!onlyIfStale && current.RefreshToken != observedRefreshToken && IsFresh(current)) return current.AccessToken!;
                }
                // Another process sharing the storage may have rotated the refresh token: the stored one is the newest.
                var stored = await ReadStoredAsync(CancellationToken.None).ConfigureAwait(false);
                if (stored?.RefreshToken != null && stored.RefreshToken != current.RefreshToken)
                {
                    current = stored;
                    _state = stored;
                    if (orgId == null && IsFresh(stored))
                    {
                        Notify();
                        return stored.AccessToken!;
                    }
                }

                JsonElement data;
                try
                {
                    // Not cancellable once sent and never retried: the refresh token rotates at every use.
                    var body = Json.Body(("refresh_token", current.RefreshToken), ("org_id", orgId));
                    data = await SendApiAsync(HttpMethod.Post, "/token/refresh", body, null, CancellationToken.None).ConfigureAwait(false);
                }
                catch (AppAuthException e) when (e.Status == 401)
                {
                    await ClearAsync().ConfigureAwait(false);
                    throw;
                }
                var next = SessionFrom(data, current.User, current.IdToken);
                var orgChanged = (next.Org?.Id ?? "") != (current.Org?.Id ?? "");
                await WriteStateAsync(next, notify: orgChanged || orgId != null).ConfigureAwait(false);
                return next.AccessToken!;
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        private StoredSession SessionFrom(JsonElement data, PoolUser? fallbackUser, string? fallbackIdToken)
        {
            var access = Json.Str(data, "access_token");
            if (string.IsNullOrEmpty(access)) throw new AppAuthException(502, "invalid_token_response", "The answer has no access token.");
            PoolUser? user = null;
            ActiveOrg? org = null;
            if (data.TryGetProperty("user", out var u) && u.ValueKind == JsonValueKind.Object) user = Json.To<PoolUser>(u);
            if (data.TryGetProperty("org", out var o) && o.ValueKind == JsonValueKind.Object) org = Json.To<ActiveOrg>(o);
            return new StoredSession
            {
                AccessToken = access,
                RefreshToken = Json.Str(data, "refresh_token"),
                IdToken = Json.Str(data, "id_token") ?? fallbackIdToken,
                ExpiresAt = _clock().ToUnixTimeMilliseconds() + (Json.Num(data, "expires_in") ?? 900) * 1000,
                User = user ?? fallbackUser,
                Org = org,
            };
        }

        private async Task<AuthOutcome> OutcomeAsync(JsonElement data)
        {
            var statusText = Json.Str(data, "status") ?? "";
            var outcome = new AuthOutcome
            {
                Status = AuthOutcome.ParseStatus(statusText),
                StatusText = statusText,
                MfaToken = Json.Str(data, "mfa_token"),
                ChangeToken = Json.Str(data, "change_token"),
            };
            if (outcome.Status == AuthStatus.Ok && Json.Str(data, "access_token") != null)
            {
                var session = SessionFrom(data, _state?.User, null);
                await WriteStateAsync(session, notify: true).ConfigureAwait(false);
                outcome.User = session.User;
                outcome.Org = session.Org;
                outcome.ExpiresIn = (int?)Json.Num(data, "expires_in");
            }
            return outcome;
        }

        private static StatusResult Status(JsonElement data) => Json.To<StatusResult>(data) ?? new StatusResult();

        private async Task<StatusResult> UserStatusAsync(JsonElement data)
        {
            var result = Status(data);
            if (result.User != null && _state != null && (_state.User == null || _state.User.Id == result.User.Id))
                await UpdateStateAsync(s => s?.WithUser(result.User), notify: true).ConfigureAwait(false);
            return result;
        }

        /// <summary>A JSON API call; <paramref name="auth"/> adds the access token (renewed when needed) and clears the
        /// session on a 401 <c>token_*</c> answer.</summary>
        private async Task<JsonElement> CallAsync(HttpMethod method, string path, object? body, bool auth, CancellationToken ct)
        {
            await InitializeAsync(ct).ConfigureAwait(false);
            string? bearer = auth ? await GetAccessTokenAsync(ct).ConfigureAwait(false) : null;
            try
            {
                return await SendApiAsync(method, path, body, bearer, ct).ConfigureAwait(false);
            }
            catch (AppAuthException e) when (auth && e.IsSessionEnded)
            {
                // Only if the session is still the one that was refused.
                if (_state?.AccessToken == bearer) await ClearAsync().ConfigureAwait(false);
                throw;
            }
        }

        private async Task<JsonElement> SendApiAsync(HttpMethod method, string path, object? body, string? bearer, CancellationToken ct)
        {
            using (var request = new HttpRequestMessage(method, Issuer + Api + path))
            {
                request.Headers.TryAddWithoutValidation("X-Client-Id", ClientId);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                if (bearer != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                if (body != null) request.Content = new StringContent(JsonSerializer.Serialize(body, Json.Options), Encoding.UTF8, "application/json");
                return await HttpCall.SendAsync(_http, request, ct).ConfigureAwait(false);
            }
        }

        private async Task<JsonElement> TokenEndpointAsync(Dictionary<string, string> form, CancellationToken ct)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, Issuer + "/token"))
            {
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                if (!string.IsNullOrEmpty(_clientSecret))
                    request.Headers.Authorization = HttpCall.BasicAuth(ClientId, _clientSecret!);
                request.Content = new FormUrlEncodedContent(form);
                return await HttpCall.SendAsync(_http, request, ct).ConfigureAwait(false);
            }
        }

        private async Task<StoredSession?> ReadStoredAsync(CancellationToken ct)
        {
            try
            {
                var text = await _storage.GetAsync(StorageKey, ct).ConfigureAwait(false);
                if (string.IsNullOrEmpty(text)) return null;
                var s = JsonSerializer.Deserialize<StoredSession>(text!, Json.Options);
                return s?.RefreshToken != null || s?.AccessToken != null ? s : null;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return null;   // unreadable: as if signed out
            }
        }

        private async Task WriteStateAsync(StoredSession? next, bool notify)
        {
            await _stateLock.WaitAsync().ConfigureAwait(false);
            try
            {
                _state = next;
                await PersistAsync(next).ConfigureAwait(false);
            }
            finally
            {
                _stateLock.Release();
            }
            if (notify) Notify();
        }

        private async Task UpdateStateAsync(Func<StoredSession?, StoredSession?> change, bool notify)
        {
            await _stateLock.WaitAsync().ConfigureAwait(false);
            try
            {
                var current = _state;
                if (current == null) return;
                var next = change(current);
                _state = next;
                await PersistAsync(next).ConfigureAwait(false);
            }
            finally
            {
                _stateLock.Release();
            }
            if (notify) Notify();
        }

        private async Task PersistAsync(StoredSession? s)
        {
            if (s?.RefreshToken != null)
                await _storage.SetAsync(StorageKey, JsonSerializer.Serialize(s, Json.Options), CancellationToken.None).ConfigureAwait(false);
            else
                await _storage.RemoveAsync(StorageKey, CancellationToken.None).ConfigureAwait(false);
        }

        private async Task ClearAsync()
        {
            var wasSignedIn = _state != null;
            await WriteStateAsync(null, notify: false).ConfigureAwait(false);
            if (wasSignedIn) Notify();
        }

        private void Notify()
        {
            var handlers = AuthStateChanged;
            if (handlers == null) return;
            var s = _state;
            var args = new AuthStateChangedEventArgs(s?.User, s?.Org, s?.AccessToken != null);
            foreach (var d in handlers.GetInvocationList())
            {
                try { ((EventHandler<AuthStateChangedEventArgs>)d)(this, args); }
                catch { /* a listener's error is its own */ }
            }
        }

        private sealed class Unsubscriber : IDisposable
        {
            private Action? _dispose;
            public Unsubscriber(Action dispose) { _dispose = dispose; }
            public void Dispose() { Interlocked.Exchange(ref _dispose, null)?.Invoke(); }
        }
    }
}
