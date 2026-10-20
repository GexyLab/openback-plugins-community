using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenBack.AppAuth
{
    /// <summary>A user of the pool as the user sees themselves (<c>PoolUser</c>). <see cref="OrgId"/>, <see cref="Roles"/>,
    /// <see cref="Providers"/> and <see cref="HasPassword"/> are filled only by <see cref="AppAuthClient.MeAsync"/>.</summary>
    public sealed class PoolUser
    {
        public string Id { get; set; } = "";
        public string? Email { get; set; }
        public bool EmailVerified { get; set; }
        public string? DisplayName { get; set; }
        public string? PhotoUrl { get; set; }
        /// <summary><c>"it"</c>, <c>"en"</c> or null.</summary>
        public string? Locale { get; set; }
        /// <summary>The custom attributes of the user (pool-defined).</summary>
        public Dictionary<string, JsonElement>? Attributes { get; set; }
        /// <summary>True for a guest account (<see cref="AppAuthClient.SignInAnonymouslyAsync"/>).</summary>
        public bool Anonymous { get; set; }
        /// <summary>ISO 8601 date-time as sent by the service.</summary>
        public string? CreatedAt { get; set; }
        /// <summary>ISO 8601 date-time as sent by the service, or null.</summary>
        public string? LastLoginAt { get; set; }
        public PoolUserMfa? Mfa { get; set; }

        // --- only in GET /me ---
        public string? OrgId { get; set; }
        public List<string>? Roles { get; set; }
        public List<LinkedProvider>? Providers { get; set; }
        public bool? HasPassword { get; set; }

        /// <summary>Members the service added after this SDK version.</summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }

        public override string ToString() => $"PoolUser({Id})";
    }

    public sealed class PoolUserMfa
    {
        /// <summary>True when an authenticator app (TOTP) is enrolled.</summary>
        public bool Totp { get; set; }
    }

    public sealed class LinkedProvider
    {
        public string ProviderId { get; set; } = "";
        public string? Kind { get; set; }
    }

    /// <summary>The organization the session is signed in to (B2B pools; null for B2C).</summary>
    public sealed class ActiveOrg
    {
        public string Id { get; set; } = "";
        public string? Name { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        /// <summary>How many organizations the user could sign in to.</summary>
        public int Choices { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }
    }

    /// <summary>The status of a sign-up / sign-in answer.</summary>
    public enum AuthStatus
    {
        /// <summary>Signed in: the SDK keeps the session.</summary>
        Ok,
        /// <summary>The email address must be verified first (a link / code was sent).</summary>
        VerificationRequired,
        /// <summary>Second factor needed: continue with <see cref="AppAuthClient.VerifyMfaAsync"/> and <see cref="AuthOutcome.MfaToken"/>.</summary>
        MfaRequired,
        /// <summary>The pool requires two-step verification and the user has none: <see cref="AppAuthClient.EnrollMfaAsync"/>
        /// then <see cref="AppAuthClient.ConfirmMfaAsync"/> with <see cref="AuthOutcome.MfaToken"/>.</summary>
        MfaEnrollRequired,
        /// <summary>The password must be changed: <see cref="AppAuthClient.ChangeForcedPasswordAsync"/> with <see cref="AuthOutcome.ChangeToken"/>.</summary>
        PasswordChangeRequired,
        /// <summary>A status this SDK version does not know (see <see cref="AuthOutcome.StatusText"/>).</summary>
        Other,
    }

    /// <summary>The outcome of a sign-up or sign-in. The tokens are kept by the client and never exposed here.</summary>
    public sealed class AuthOutcome
    {
        public AuthStatus Status { get; internal set; }
        /// <summary>The status as sent by the service (<c>ok</c>, <c>mfa_required</c>...).</summary>
        public string StatusText { get; internal set; } = "";
        public bool IsOk => Status == AuthStatus.Ok;
        /// <summary>The signed-in user (status Ok).</summary>
        public PoolUser? User { get; internal set; }
        /// <summary>The active organization (status Ok, B2B pools).</summary>
        public ActiveOrg? Org { get; internal set; }
        /// <summary>For <see cref="AuthStatus.MfaRequired"/> and <see cref="AuthStatus.MfaEnrollRequired"/>.</summary>
        public string? MfaToken { get; internal set; }
        /// <summary>For <see cref="AuthStatus.PasswordChangeRequired"/>.</summary>
        public string? ChangeToken { get; internal set; }
        /// <summary>Seconds of life of the new access token (status Ok).</summary>
        public int? ExpiresIn { get; internal set; }

        internal static AuthStatus ParseStatus(string? status)
        {
            switch (status)
            {
                case "ok": return AuthStatus.Ok;
                case "verification_required": return AuthStatus.VerificationRequired;
                case "mfa_required": return AuthStatus.MfaRequired;
                case "mfa_enroll_required": return AuthStatus.MfaEnrollRequired;
                case "password_change_required": return AuthStatus.PasswordChangeRequired;
                default: return AuthStatus.Other;
            }
        }

        public override string ToString() => $"AuthOutcome({StatusText})";
    }

    /// <summary>A simple answer such as <c>{"status": "sent"}</c>.</summary>
    public sealed class StatusResult
    {
        public string Status { get; set; } = "";
        /// <summary>The user, when the answer carries one (email verified or changed, guest upgraded).</summary>
        public PoolUser? User { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }
    }

    /// <summary>A new authenticator app to enroll: show <see cref="OtpauthUri"/> as a QR code (or the secret).</summary>
    public sealed class MfaEnrollment
    {
        public string Secret { get; set; } = "";
        [JsonPropertyName("otpauth_uri")]
        public string OtpauthUri { get; set; } = "";

        public override string ToString() => "MfaEnrollment(***)";
    }

    /// <summary>The answer of <see cref="AppAuthClient.ConfirmMfaAsync"/>: the recovery codes (show them once) and, when the
    /// enrollment was part of a sign-in (with an MFA token), the sign-in outcome.</summary>
    public sealed class MfaConfirmation
    {
        public IReadOnlyList<string> RecoveryCodes { get; internal set; } = Array.Empty<string>();
        public AuthOutcome? Outcome { get; internal set; }

        public override string ToString() => $"MfaConfirmation({RecoveryCodes.Count} recovery codes)";
    }

    /// <summary>The public configuration of the pool (<c>GET /config</c>).</summary>
    public sealed class PoolConfig
    {
        public string Issuer { get; set; } = "";
        /// <summary><c>b2c</c> or <c>b2b</c>.</summary>
        public string? Mode { get; set; }
        /// <summary>The enabled sign-in methods (pool-defined object).</summary>
        public JsonElement? Methods { get; set; }
        /// <summary>Sign-up settings (pool-defined object).</summary>
        public JsonElement? Signup { get; set; }
        public bool HostedLogin { get; set; }
        public JsonElement? PasswordPolicy { get; set; }
        /// <summary>Two-step verification mode of the pool.</summary>
        public string? Mfa { get; set; }
        public PoolOrgSettings? Orgs { get; set; }
        public List<PoolProvider> Providers { get; set; } = new List<PoolProvider>();
        public PoolBranding? Branding { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }
    }

    public sealed class PoolOrgSettings
    {
        public bool SelfService { get; set; }
    }

    /// <summary>A sign-in provider (Google, Microsoft...): pass its <see cref="Id"/> as
    /// <see cref="AuthorizationRequestOptions.Provider"/>.</summary>
    public sealed class PoolProvider
    {
        public string Id { get; set; } = "";
        public string? Kind { get; set; }
        public string? Label { get; set; }
        public string? StartUrl { get; set; }
    }

    public sealed class PoolBranding
    {
        public string? DisplayName { get; set; }
        public string? LogoUrl { get; set; }
        public string? PrimaryColor { get; set; }
        public string? DefaultLanguage { get; set; }
        public string? TermsUrl { get; set; }
        public string? PrivacyUrl { get; set; }
    }

    /// <summary>Profile fields to change; null fields are left as they are.</summary>
    public sealed class ProfileUpdate
    {
        public string? DisplayName { get; set; }
        public string? PhotoUrl { get; set; }
        /// <summary><c>"it"</c> or <c>"en"</c>.</summary>
        public string? Locale { get; set; }
    }

    /// <summary>The user's organizations (<c>GET /orgs</c>); empty for B2C pools.</summary>
    public sealed class OrganizationList
    {
        public List<OrganizationMembership> Orgs { get; set; } = new List<OrganizationMembership>();
        /// <summary>The id of the active organization.</summary>
        public string? Active { get; set; }
    }

    public sealed class OrganizationMembership
    {
        public string Id { get; set; } = "";
        public string? Name { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public bool Disabled { get; set; }
    }

    public sealed class OrgMemberPage
    {
        public List<OrgMember> Items { get; set; } = new List<OrgMember>();
        public int? Total { get; set; }
        /// <summary>The roles that can be given in the pool.</summary>
        public List<OrgRole> Roles { get; set; } = new List<OrgRole>();
    }

    public sealed class OrgMember
    {
        public string UserId { get; set; } = "";
        public string? Email { get; set; }
        public string? DisplayName { get; set; }
        public bool? Disabled { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public string? CreatedAt { get; set; }
    }

    public sealed class OrgRole
    {
        public string Key { get; set; } = "";
        public string? Label { get; set; }
    }

    /// <summary>The answer of <see cref="AppAuthClient.AddMemberAsync"/>.</summary>
    public sealed class AddedMember
    {
        public string UserId { get; set; } = "";
        public string? Email { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        /// <summary>True when a new account was made for the address.</summary>
        public bool Created { get; set; }
        /// <summary>For a new account without a given password: a temporary password, shown once (hand it over; it must
        /// be changed at the first sign-in). Never log it.</summary>
        public string? TemporaryPassword { get; set; }

        public override string ToString() => $"AddedMember({UserId})";
    }

    public sealed class MemberRoles
    {
        public string UserId { get; set; } = "";
        public List<string> Roles { get; set; } = new List<string>();
    }

    /// <summary>The state change raised by <see cref="AppAuthClient.AuthStateChanged"/>.</summary>
    public sealed class AuthStateChangedEventArgs : EventArgs
    {
        public AuthStateChangedEventArgs(PoolUser? user, ActiveOrg? org, bool isSignedIn)
        {
            User = user;
            Org = org;
            IsSignedIn = isSignedIn;
        }

        /// <summary>The signed-in user, or null when signed out.</summary>
        public PoolUser? User { get; }
        public ActiveOrg? Org { get; }
        /// <summary>True while a session is kept (the user can be null for a moment after a hosted sign-in whose
        /// profile could not be read).</summary>
        public bool IsSignedIn { get; }
    }
}
