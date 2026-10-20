import Foundation

/// The client of an OpenBack user pool (users-service, "App authenticator").
///
/// ```swift
/// let auth = AppAuthClient(issuer: "https://api.example.com/gateway/shop/auth/main",
///                          clientId: "uapp_...",
///                          redirectURI: "com.example.app:/oauth2redirect")
/// let outcome = try await auth.signInWithPassword(email: email, password: password)
/// let token = try await auth.accessToken()
/// ```
///
/// Two ways to sign users in, freely mixed: your own screens (`signUp`, `signInWithPassword`, `signInWithEmailCode`,
/// `signInAnonymously`, `verifyMfa`) call the pool's JSON API; `signInWithHostedPage` opens the pool's hosted page
/// (OpenID Connect, authorization code + PKCE) in `ASWebAuthenticationSession`.
///
/// It is an actor: the session and the token renewal are serialized. The access token is renewed one minute before it
/// expires, one renewal at a time (refresh tokens rotate at every use). The session lives in a `TokenStorage`
/// (`KeychainTokenStorage` by default). For SwiftUI, wrap it in `AppAuthModel`.
public actor AppAuthClient {
    private struct Settings: Sendable {
        let issuer: String
        let clientId: String
        let redirectURI: String?
        let storageKey: String
    }

    // Immutable and Sendable: readable without isolation.
    private let settings: Settings

    /// The pool's address (no trailing slash).
    public nonisolated var issuer: String { settings.issuer }
    /// The app's client ID (`uapp_...`).
    public nonisolated var clientId: String { settings.clientId }
    /// The app's registered redirect address for the hosted sign-in (e.g. `com.example.app:/oauth2redirect`).
    public nonisolated var redirectURI: String? { settings.redirectURI }
    /// The storage key of the session (`openback.auth.<clientId>`).
    public nonisolated var storageKey: String { settings.storageKey }

    private let storage: any TokenStorage
    private let urlSession: URLSession
    private let webAuthenticator: (any WebAuthenticator)?
    private let clock: @Sendable () -> Date

    private var current: StoredSession?
    private var loaded = false
    private var rotation: Task<String, Error>?
    private var listeners: [UUID: AsyncStream<AuthState>.Continuation] = [:]

    private static let skew: TimeInterval = 60
    private static let api = "/api/v1"

    /// Creates a client of the pool at `issuer` (trailing slashes removed) for the app `clientId`.
    ///
    /// - Parameters:
    ///   - redirectURI: needed by the hosted sign-in only.
    ///   - storage: default `KeychainTokenStorage()`.
    ///   - storageKey: default `openback.auth.<clientId>`.
    ///   - urlSession: the session for the pool's calls (default `.shared`).
    ///   - webAuthenticator: the authentication browser (default `SystemWebAuthenticator` on iOS/macOS).
    ///   - clock: the current time (tests).
    public init(issuer: String,
                clientId: String,
                redirectURI: String? = nil,
                storage: (any TokenStorage)? = nil,
                storageKey: String? = nil,
                urlSession: URLSession = .shared,
                webAuthenticator: (any WebAuthenticator)? = nil,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        var trimmed = issuer.trimmingCharacters(in: .whitespacesAndNewlines)
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        precondition(!trimmed.isEmpty && !clientId.isEmpty, "AppAuthClient: issuer and clientId are required")
        settings = Settings(issuer: trimmed, clientId: clientId, redirectURI: redirectURI,
                            storageKey: storageKey ?? "openback.auth.\(clientId)")
        self.storage = storage ?? KeychainTokenStorage()
        self.urlSession = urlSession
        self.webAuthenticator = webAuthenticator ?? AppAuthClient.defaultWebAuthenticator()
        self.clock = clock
    }

    private var pendingKey: String { storageKey + ".pkce" }

    // MARK: - State

    // Reads the stored session once. A Keychain that cannot be read yet (before the first unlock) is retried later.
    private func ensureLoaded() {
        guard !loaded else { return }
        do {
            if let raw = try storage.get(storageKey), let data = raw.data(using: .utf8) {
                current = try? JSONDecoder().decode(StoredSession.self, from: data)
            }
            loaded = true
        } catch {
            current = nil
        }
    }

    private func save(_ next: StoredSession?) throws {
        current = next
        loaded = true
        defer { broadcast() }
        if let next, !next.refreshToken.isEmpty {
            let data = try JSONEncoder().encode(next)
            try storage.set(String(decoding: data, as: UTF8.self), for: storageKey)
        } else {
            try storage.remove(storageKey)
        }
    }

    private func clear() {
        try? save(nil)
    }

    private var state: AuthState {
        guard let session = current else { return .signedOut }
        return AuthState(user: session.user ?? Self.userFromClaims(session.accessToken), org: session.org)
    }

    // Until /me answers (hosted sign-in), the user known from the access token.
    private static func userFromClaims(_ token: String) -> PoolUser? {
        guard let claims = JWT.decodePayload(token), let sub = claims["sub"]?.stringValue else { return nil }
        return PoolUser(id: sub,
                        email: claims["email"]?.stringValue,
                        emailVerified: claims["email_verified"]?.boolValue ?? false,
                        displayName: claims["name"]?.stringValue ?? "",
                        attributes: claims["attr"]?.objectValue ?? [:],
                        anonymous: claims["anon"]?.boolValue ?? false)
    }

    private func broadcast() {
        let value = state
        for continuation in listeners.values { continuation.yield(value) }
    }

    /// The signed-in user (nil when signed out).
    public var currentUser: PoolUser? {
        ensureLoaded()
        return state.user
    }

    /// The active organization (B2B pools; nil in B2C pools).
    public var currentOrg: ActiveOrg? {
        ensureLoaded()
        return state.org
    }

    /// The current state (user and organization).
    public var authState: AuthState {
        ensureLoaded()
        return state
    }

    /// Whether a session is stored.
    public var isSignedIn: Bool {
        ensureLoaded()
        return current != nil
    }

    /// The access token's claims, decoded but NOT verified (for display: roles, permissions, org_id).
    public var accessTokenClaims: [String: JSONValue]? {
        ensureLoaded()
        return current.flatMap { JWT.decodePayload($0.accessToken) }
    }

    /// The state now and at every change (sign-in, renewal, profile update, sign-out). Stop by cancelling the task
    /// that iterates it.
    public nonisolated func authStateChanges() -> AsyncStream<AuthState> {
        AsyncStream(bufferingPolicy: .bufferingNewest(16)) { continuation in
            let id = UUID()
            continuation.onTermination = { @Sendable _ in
                Task { await self.removeListener(id) }
            }
            Task { await self.addListener(id, continuation) }
        }
    }

    /// Calls `listener` now and at every change, until the returned subscription is cancelled.
    @discardableResult
    public nonisolated func onAuthStateChanged(_ listener: @escaping @Sendable (AuthState) -> Void) -> AuthStateSubscription {
        let stream = authStateChanges()
        return AuthStateSubscription(task: Task {
            for await value in stream { listener(value) }
        })
    }

    private func addListener(_ id: UUID, _ continuation: AsyncStream<AuthState>.Continuation) {
        ensureLoaded()
        listeners[id] = continuation
        continuation.yield(state)
    }

    private func removeListener(_ id: UUID) {
        listeners[id] = nil
    }

    // MARK: - HTTP

    private static func body(_ pairs: KeyValuePairs<String, JSONValue?>) -> [String: JSONValue] {
        var out: [String: JSONValue] = [:]
        for (key, value) in pairs {
            if let value { out[key] = value }
        }
        return out
    }

    private func perform(_ request: URLRequest) async throws -> (Data, Int) {
        do {
            let (data, response) = try await urlSession.data(for: request)
            return (data, (response as? HTTPURLResponse)?.statusCode ?? 0)
        } catch {
            throw AppAuthError.network(error)
        }
    }

    private func send(_ method: String, _ path: String, body: [String: JSONValue]? = nil,
                      auth: Bool = false, bearer: String? = nil) async throws -> Data {
        ensureLoaded()
        guard let url = URL(string: issuer + Self.api + path) else {
            throw AppAuthError(status: 0, code: "invalid_url", message: "Invalid address")
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue(clientId, forHTTPHeaderField: "X-Client-Id")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        var token = bearer
        if token == nil && auth { token = try await accessToken() }
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(body)
        }
        let (data, status) = try await perform(request)
        guard (200..<300).contains(status) else {
            let error = AppAuthError.fromAPI(status: status, data: data)
            if status == 401 && (error.code == "invalid_refresh_token" || (token != nil && error.code.hasPrefix("token_"))) {
                clear() // the session is dead: signed out
            }
            throw error
        }
        return data
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw AppAuthError.unexpected("Unexpected answer from the user pool")
        }
    }

    private func json<T: Decodable>(_ type: T.Type, _ method: String, _ path: String, body: [String: JSONValue]? = nil,
                                    auth: Bool = false, bearer: String? = nil) async throws -> T {
        try decode(type, try await send(method, path, body: body, auth: auth, bearer: bearer))
    }

    private func tokenEndpoint(_ form: [(String, String)]) async throws -> TokenWire {
        guard let url = URL(string: issuer + "/token") else {
            throw AppAuthError(status: 0, code: "invalid_url", message: "Invalid address")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = Data(FormEncoding.encode(form).utf8)
        let (data, status) = try await perform(request)
        guard (200..<300).contains(status) else { throw AppAuthError.fromOAuth(status: status, data: data) }
        return try decode(TokenWire.self, data)
    }

    // An outcome of a sign-up or sign-in: the session is kept only when "ok".
    private func outcome(_ wire: TokenWire) throws -> SignInOutcome {
        switch wire.status ?? "" {
        case "ok":
            if wire.accessToken != nil { try store(wire, user: wire.user, newSignIn: true) }
            return .ok(user: wire.user, org: wire.org)
        case "verification_required":
            return .verificationRequired
        case "mfa_required":
            return .mfaRequired(mfaToken: wire.mfaToken ?? "")
        case "mfa_enroll_required":
            return .mfaEnrollRequired(mfaToken: wire.mfaToken ?? "")
        case "password_change_required":
            return .passwordChangeRequired(changeToken: wire.changeToken ?? "")
        default:
            throw AppAuthError.unexpected("Unknown sign-in status: \(wire.status ?? "none")")
        }
    }

    private func store(_ wire: TokenWire, user: PoolUser? = nil, newSignIn: Bool = false) throws {
        guard let access = wire.accessToken else { throw AppAuthError.unexpected("No access token in the answer") }
        let previous = newSignIn ? nil : current
        let expiresIn = wire.expiresIn ?? 900
        let expiresAt = Int64(((clock().timeIntervalSince1970 + expiresIn) * 1000).rounded())
        try save(StoredSession(accessToken: access,
                               refreshToken: wire.refreshToken ?? previous?.refreshToken ?? "",
                               idToken: wire.idToken ?? previous?.idToken,
                               expiresAt: expiresAt,
                               user: user ?? previous?.user,
                               org: wire.org))
    }

    private func setUser(_ user: PoolUser) {
        guard var session = current else { return }
        if let known = session.user ?? Self.userFromClaims(session.accessToken), known.id != user.id { return }
        session.user = user
        try? save(session)
    }

    private func patchUser(_ change: (inout PoolUser) -> Void) {
        guard var session = current, var user = session.user else { return }
        change(&user)
        session.user = user
        try? save(session)
    }

    // MARK: - Tokens

    private func isFresh(_ session: StoredSession) -> Bool {
        Double(session.expiresAt) / 1000 - clock().timeIntervalSince1970 > Self.skew
    }

    /// A valid access token: the stored one if it expires in more than 60 s, else a renewed one.
    /// Throws `AppAuthError.notSignedIn` when signed out.
    public func accessToken() async throws -> String {
        ensureLoaded()
        guard let session = current else { throw AppAuthError.notSignedIn }
        if isFresh(session) { return session.accessToken }
        return try await refresh()
    }

    /// Renews the tokens now (optionally for the organization `orgId`). One renewal at a time: concurrent callers share
    /// it. A network failure is thrown and never retried automatically (the refresh token rotates); the next call
    /// tries again with the stored token. A refused refresh token clears the session.
    @discardableResult
    public func refresh(orgId: String? = nil) async throws -> String {
        ensureLoaded()
        while let running = rotation {
            if orgId == nil { return try await running.value }
            _ = try? await running.value
            if rotation == running { rotation = nil }
        }
        return try await exclusive { try await self.performRefresh(orgId: orgId) }
    }

    // Runs an operation that rotates the refresh token, never two at once. `rotation` is set with no suspension point
    // after the check (the loop awaits only while something runs), so concurrent callers always see it.
    private func exclusive(_ operation: @escaping @Sendable () async throws -> String) async throws -> String {
        while let running = rotation {
            _ = try? await running.value
            if rotation == running { rotation = nil } // finished: free the slot
        }
        let task = Task { try await operation() }
        rotation = task
        defer { if rotation == task { rotation = nil } }
        return try await task.value
    }

    private func waitForRotation() async {
        while let running = rotation {
            _ = try? await running.value
            if rotation == running { rotation = nil } // finished: free the slot
        }
    }

    private func performRefresh(orgId: String?) async throws -> String {
        guard let session = current else { throw AppAuthError.notSignedIn }
        let wire = try await json(TokenWire.self, "POST", "/token/refresh",
                                  body: Self.body(["refresh_token": .string(session.refreshToken),
                                                   "org_id": orgId.map(JSONValue.string)]))
        return try afterRotation(used: session, wire)
    }

    private func afterRotation(used: StoredSession, _ wire: TokenWire) throws -> String {
        guard let access = wire.accessToken else { throw AppAuthError.unexpected("No access token in the answer") }
        guard current?.refreshToken == used.refreshToken else {
            throw AppAuthError(status: 401, code: "not_signed_in", message: "The session changed while it was being renewed")
        }
        try store(wire)
        return access
    }

    /// `request` with `Authorization: Bearer <access token>` (renewed when needed).
    public func authorize(_ request: URLRequest) async throws -> URLRequest {
        let token = try await accessToken()
        var authorized = request
        authorized.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return authorized
    }

    // MARK: - Configuration

    /// The pool's public settings: methods, providers, password policy, mode, branding.
    public func config() async throws -> PoolConfig {
        try await json(PoolConfig.self, "GET", "/config")
    }

    // MARK: - Sign-up and sign-in

    /// Creates an account with email and password.
    public func signUp(email: String, password: String, displayName: String? = nil, locale: String? = nil,
                       orgId: String? = nil) async throws -> SignInOutcome {
        try outcome(try await json(TokenWire.self, "POST", "/signup", body: Self.body([
            "email": .string(email), "password": .string(password), "display_name": .string(displayName ?? ""),
            "locale": locale.map(JSONValue.string), "org_id": orgId.map(JSONValue.string),
        ])))
    }

    /// Signs in with email and password.
    public func signInWithPassword(email: String, password: String, orgId: String? = nil) async throws -> SignInOutcome {
        try outcome(try await json(TokenWire.self, "POST", "/signin/password", body: Self.body([
            "email": .string(email), "password": .string(password), "org_id": orgId.map(JSONValue.string),
        ])))
    }

    /// Emails a sign-in code (the answer never tells whether the address has an account).
    public func sendEmailCode(email: String) async throws {
        _ = try await send("POST", "/signin/email-code", body: ["email": .string(email)])
    }

    /// Signs in with the emailed code (`email` + `code`) or the link's `token`.
    public func signInWithEmailCode(email: String? = nil, code: String? = nil, token: String? = nil,
                                    orgId: String? = nil) async throws -> SignInOutcome {
        try outcome(try await json(TokenWire.self, "POST", "/signin/email-code/verify", body: Self.body([
            "email": email.map(JSONValue.string), "code": code.map(JSONValue.string),
            "token": token.map(JSONValue.string), "org_id": orgId.map(JSONValue.string),
        ])))
    }

    /// Signs in as a guest (if the pool allows it); `upgradeAnonymous` turns the guest into a real account.
    public func signInAnonymously() async throws -> SignInOutcome {
        try outcome(try await json(TokenWire.self, "POST", "/signin/anonymous", body: [:]))
    }

    /// Completes a sign-in that answered `.mfaRequired`, with a TOTP or recovery `code`.
    public func verifyMfa(mfaToken: String, code: String) async throws -> SignInOutcome {
        try outcome(try await json(TokenWire.self, "POST", "/signin/mfa",
                                   body: ["mfa_token": .string(mfaToken), "code": .string(code)]))
    }

    /// Starts a TOTP enrollment: during a sign-in (`.mfaEnrollRequired`) pass its `mfaToken`; signed in, omit it.
    public func enrollMfa(mfaToken: String? = nil) async throws -> MfaEnrollment {
        if let mfaToken {
            return try await json(MfaEnrollment.self, "POST", "/mfa/enroll", body: ["mfa_token": .string(mfaToken)])
        }
        return try await json(MfaEnrollment.self, "POST", "/mfa/enroll", body: [:], auth: true)
    }

    /// Confirms the enrollment with a first `code`. With `mfaToken` the sign-in completes (`outcome`).
    public func confirmMfa(code: String, mfaToken: String? = nil) async throws -> MfaConfirmation {
        if let mfaToken {
            let data = try await send("POST", "/mfa/enroll/confirm", body: ["mfa_token": .string(mfaToken), "code": .string(code)])
            let wire = try decode(TokenWire.self, data)
            return MfaConfirmation(recoveryCodes: wire.recoveryCodes ?? [], outcome: try outcome(wire))
        }
        let wire = try await json(RecoveryWire.self, "POST", "/mfa/enroll/confirm", body: ["code": .string(code)], auth: true)
        patchUser { $0.mfa.totp = true }
        return MfaConfirmation(recoveryCodes: wire.recoveryCodes ?? [], outcome: nil)
    }

    /// Turns two-step verification off (signed in; a current `code` is required).
    public func disableMfa(code: String) async throws {
        _ = try await send("POST", "/mfa/disable", body: ["code": .string(code)], auth: true)
        patchUser { $0.mfa.totp = false }
    }

    // MARK: - Passwords and emails

    /// Emails a password reset code and link (always answers the same way).
    public func sendPasswordReset(email: String) async throws {
        _ = try await send("POST", "/password/forgot", body: ["email": .string(email)])
    }

    /// Sets a new password with the reset link's `token`, or with `email` + `code`.
    public func resetPassword(token: String? = nil, email: String? = nil, code: String? = nil,
                              newPassword: String) async throws {
        _ = try await send("POST", "/password/reset", body: Self.body([
            "token": token.map(JSONValue.string), "email": email.map(JSONValue.string),
            "code": code.map(JSONValue.string), "new_password": .string(newPassword),
        ]))
    }

    /// Sets the new password a `.passwordChangeRequired` outcome asked for; then sign in again.
    public func changeForcedPassword(changeToken: String, newPassword: String) async throws {
        _ = try await send("POST", "/password/reset",
                           body: ["change_token": .string(changeToken), "new_password": .string(newPassword)])
    }

    /// Verifies the email address with the link's `token` or `email` + `code`; returns the user.
    @discardableResult
    public func verifyEmail(token: String? = nil, email: String? = nil, code: String? = nil) async throws -> PoolUser? {
        let wire = try await json(UserWire.self, "POST", "/email/verify", body: Self.body([
            "token": token.map(JSONValue.string), "email": email.map(JSONValue.string), "code": code.map(JSONValue.string),
        ]))
        if let user = wire.user { setUser(user) }
        return wire.user
    }

    /// Sends the verification email again (signed in).
    public func resendVerification() async throws {
        _ = try await send("POST", "/email/verify/send", body: [:], auth: true)
    }

    // MARK: - The signed-in user

    /// The signed-in user, fresh from the pool (also updates `currentUser`).
    @discardableResult
    public func me() async throws -> PoolUser {
        let user = try await json(PoolUser.self, "GET", "/me", auth: true)
        setUser(user)
        return user
    }

    /// Updates the profile (only the fields given).
    @discardableResult
    public func updateProfile(displayName: String? = nil, photoURL: String? = nil, locale: String? = nil) async throws -> PoolUser {
        let user = try await json(PoolUser.self, "PATCH", "/me", body: Self.body([
            "display_name": displayName.map(JSONValue.string), "photo_url": photoURL.map(JSONValue.string),
            "locale": locale.map(JSONValue.string),
        ]), auth: true)
        setUser(user)
        return user
    }

    /// Changes the password. Every session of the user ends, this one too: the local session is cleared.
    public func changePassword(currentPassword: String? = nil, newPassword: String) async throws {
        _ = try await send("POST", "/me/password", body: Self.body([
            "current_password": currentPassword.map(JSONValue.string), "new_password": .string(newPassword),
        ]), auth: true)
        clear()
    }

    /// Starts an email change: a code is sent to `newEmail` (`confirmEmailChange`).
    public func changeEmail(newEmail: String) async throws {
        _ = try await send("POST", "/me/email", body: ["new_email": .string(newEmail)], auth: true)
    }

    /// Confirms the email change with the `code` or the link's `token`; returns the user.
    @discardableResult
    public func confirmEmailChange(code: String? = nil, token: String? = nil) async throws -> PoolUser? {
        let wire = try await json(UserWire.self, "POST", "/me/email/confirm", body: Self.body([
            "code": code.map(JSONValue.string), "token": token.map(JSONValue.string),
        ]), auth: true)
        if let user = wire.user { setUser(user) }
        return wire.user
    }

    /// Turns the signed-in guest into a real account (same id), then renews the tokens (best effort).
    @discardableResult
    public func upgradeAnonymous(email: String, password: String) async throws -> PoolUser? {
        let wire = try await json(UserWire.self, "POST", "/me/upgrade",
                                  body: ["email": .string(email), "password": .string(password)], auth: true)
        if let user = wire.user { setUser(user) }
        _ = try? await refresh() // the access token says "anon" until renewed
        return wire.user
    }

    /// Deletes the account (`password` required when it has one) and clears the local session.
    public func deleteAccount(password: String? = nil) async throws {
        _ = try await send("DELETE", "/me", body: Self.body(["password": password.map(JSONValue.string)]), auth: true)
        clear()
    }

    /// Signs out: tells the pool (best effort: revokes the refresh token, ends this session or, with `everywhere`, all
    /// the user's sessions) and always clears the local session.
    public func signOut(everywhere: Bool = false) async {
        ensureLoaded()
        await waitForRotation()
        if var session = current {
            do {
                var bearer: String? = isFresh(session) ? session.accessToken : nil
                if bearer == nil && everywhere {
                    bearer = try await accessToken() // "everywhere" needs a valid access token
                    session = current ?? session
                }
                _ = try await send("POST", "/signout", body: ["refresh_token": .string(session.refreshToken),
                                                             "everywhere": .bool(everywhere)], bearer: bearer)
            } catch {
                // signed out locally anyway
            }
        }
        clear()
    }

    // MARK: - Organizations (B2B pools)

    /// The user's organizations and the active one (B2C pools: empty).
    public func organizations() async throws -> OrganizationList {
        try await json(OrganizationList.self, "GET", "/orgs", auth: true)
    }

    /// Creates an organization (if the pool allows it); the user becomes its owner.
    public func createOrganization(name: String) async throws -> Organization {
        try await json(Organization.self, "POST", "/orgs", body: ["name": .string(name)], auth: true)
    }

    /// Switches the session to the organization `orgId` (new tokens); returns the new active organization.
    @discardableResult
    public func switchOrganization(_ orgId: String) async throws -> ActiveOrg? {
        let bearer = try await accessToken()
        _ = try await exclusive { try await self.performSwitch(orgId: orgId, bearer: bearer) }
        return current?.org
    }

    private func performSwitch(orgId: String, bearer: String) async throws -> String {
        guard let session = current else { throw AppAuthError.notSignedIn }
        let wire = try await json(TokenWire.self, "POST", "/orgs/switch",
                                  body: ["org_id": .string(orgId), "refresh_token": .string(session.refreshToken)],
                                  bearer: bearer)
        return try afterRotation(used: session, wire)
    }

    private func membersPath(_ orgId: String, _ userId: String? = nil) -> String {
        var path = "/orgs/\(FormEncoding.escape(orgId))/members"
        if let userId { path += "/\(FormEncoding.escape(userId))" }
        return path
    }

    /// A page of the organization's members (owners and admins only).
    public func members(orgId: String, query: String = "", skip: Int = 0, limit: Int = 50) async throws -> MemberPage {
        let q = FormEncoding.encode([("q", query), ("skip", String(skip)), ("limit", String(limit))])
        return try await json(MemberPage.self, "GET", membersPath(orgId) + "?" + q, auth: true)
    }

    /// Adds a member: an existing user joins; an unknown address gets an account with a temporary password.
    public func addMember(orgId: String, email: String, displayName: String? = nil, password: String? = nil,
                          roles: [String] = []) async throws -> AddedMember {
        try await json(AddedMember.self, "POST", membersPath(orgId), body: Self.body([
            "email": .string(email), "display_name": .string(displayName ?? ""),
            "password": password.map(JSONValue.string), "roles": .array(roles.map(JSONValue.string)),
        ]), auth: true)
    }

    /// Sets a member's roles; returns them.
    @discardableResult
    public func setMemberRoles(orgId: String, userId: String, roles: [String]) async throws -> [String] {
        try await json(RolesWire.self, "PATCH", membersPath(orgId, userId),
                       body: ["roles": .array(roles.map(JSONValue.string))], auth: true).roles ?? roles
    }

    /// Removes a member from the organization.
    public func removeMember(orgId: String, userId: String) async throws {
        _ = try await send("DELETE", membersPath(orgId, userId), auth: true)
    }

    // MARK: - Hosted sign-in (OpenID Connect)

    /// Builds the `<issuer>/authorize` address (code + PKCE S256, state, nonce) and stores the transaction for
    /// `handleRedirectCallback`. Low level: `signInWithHostedPage` does everything.
    public func buildAuthorizationRequest(_ options: AuthorizationOptions = AuthorizationOptions(),
                                          redirectURI: String? = nil) throws -> AuthorizationRequest {
        ensureLoaded()
        guard let redirect = redirectURI ?? self.redirectURI, !redirect.isEmpty else {
            throw AppAuthError(status: 0, code: "missing_redirect_uri", message: "redirectURI is required for the hosted sign-in")
        }
        let verifier = try PKCE.codeVerifier()
        let state = try PKCE.randomString(24)
        let nonce = try PKCE.randomString(24)
        var items: [(String, String)] = [
            ("response_type", "code"), ("client_id", clientId), ("redirect_uri", redirect), ("scope", options.scope),
            ("state", state), ("nonce", nonce), ("code_challenge", PKCE.codeChallenge(for: verifier)),
            ("code_challenge_method", "S256"),
        ]
        if let value = options.provider { items.append(("provider", value)) }
        if let value = options.orgId { items.append(("org_id", value)) }
        if let value = options.prompt { items.append(("prompt", value)) }
        if let value = options.screenHint { items.append(("screen_hint", value)) }
        if let value = options.loginHint { items.append(("login_hint", value)) }
        if let value = options.maxAge { items.append(("max_age", String(value))) }
        if let value = options.uiLocales { items.append(("ui_locales", value)) }
        guard let url = URL(string: issuer + "/authorize?" + FormEncoding.encode(items)) else {
            throw AppAuthError(status: 0, code: "invalid_url", message: "Invalid address")
        }
        let request = AuthorizationRequest(url: url, state: state, nonce: nonce, codeVerifier: verifier, redirectURI: redirect)
        try storage.set(String(decoding: try JSONEncoder().encode(request), as: UTF8.self), for: pendingKey)
        return request
    }

    private func takePending() -> AuthorizationRequest? {
        let raw = try? storage.get(pendingKey)
        try? storage.remove(pendingKey) // one use
        guard let raw, let data = raw.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(AuthorizationRequest.self, from: data)
    }

    /// Completes a hosted sign-in from the callback address: checks `error`, `state` (constant time) and `iss`,
    /// exchanges the code (PKCE), checks the ID token's `nonce`, `aud` and `iss` (decoded, not verified: it comes
    /// straight from the token endpoint over TLS), stores the session and returns the user.
    @discardableResult
    public func handleRedirectCallback(_ url: URL) async throws -> PoolUser? {
        ensureLoaded()
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func param(_ name: String) -> String? { items.first { $0.name == name }?.value }
        let pending = takePending()
        if let error = param("error") {
            let description = param("error_description")?.replacingOccurrences(of: "+", with: " ")
            throw AppAuthError.callback(error, description ?? error)
        }
        guard let code = param("code"), !code.isEmpty else {
            throw AppAuthError.callback("invalid_callback", "The callback carries no authorization code")
        }
        guard let pending, PKCE.constantTimeEquals(pending.state, param("state") ?? "") else {
            throw AppAuthError.callback("invalid_state", "Sign-in state mismatch")
        }
        if let iss = param("iss"), iss != issuer {
            throw AppAuthError.callback("invalid_issuer", "Unexpected issuer")
        }
        let wire = try await tokenEndpoint([
            ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", pending.redirectURI),
            ("client_id", clientId), ("code_verifier", pending.codeVerifier),
        ])
        if let idToken = wire.idToken {
            guard let claims = JWT.decodePayload(idToken) else {
                throw AppAuthError.callback("invalid_id_token", "Unreadable ID token")
            }
            guard let nonce = claims["nonce"]?.stringValue, PKCE.constantTimeEquals(nonce, pending.nonce) else {
                throw AppAuthError.callback("invalid_nonce", "Nonce mismatch")
            }
            let aud = claims["aud"]
            let audienceMatches = aud?.stringValue == clientId || (aud?.arrayValue?.contains(.string(clientId)) ?? false)
            guard audienceMatches, claims["iss"]?.stringValue == issuer else {
                throw AppAuthError.callback("invalid_id_token", "ID token of another app or issuer")
            }
        }
        try store(wire, newSignIn: true)
        do {
            return try await me()
        } catch is AppAuthError {
            return state.user // known from the token until /me answers
        }
    }

    private func callbackURL(_ address: String) throws -> URL {
        guard let url = URL(string: address), url.scheme != nil else {
            throw AppAuthError(status: 0, code: "invalid_redirect_uri", message: "Invalid redirect address")
        }
        return url
    }

    /// Signs in through the pool's hosted page in the system authentication browser and returns the user.
    /// Throws `AppAuthError.canceled` when the user closes it.
    ///
    /// - Parameter prefersEphemeralSession: a private browser session: no cookies shared with Safari and no "wants to
    ///   use ... to sign in" prompt, but the user signs in every time.
    @discardableResult
    public func signInWithHostedPage(_ options: AuthorizationOptions = AuthorizationOptions(),
                                     prefersEphemeralSession: Bool = false) async throws -> PoolUser? {
        guard let webAuthenticator else {
            throw AppAuthError(status: 0, code: "unsupported_platform",
                               message: "No authentication browser on this platform: pass a WebAuthenticator")
        }
        let request = try buildAuthorizationRequest(options)
        let callback: URL
        do {
            callback = try await webAuthenticator.authenticate(url: request.url,
                                                               callbackURL: try callbackURL(request.redirectURI),
                                                               prefersEphemeralSession: prefersEphemeralSession)
        } catch {
            try? storage.remove(pendingKey)
            throw error
        }
        return try await handleRedirectCallback(callback)
    }

    /// The pool's end-session address (`<issuer>/logout`) with `client_id`, `id_token_hint`, the post-logout redirect
    /// address (must be in the app's post-logout list) and `state`.
    public func buildLogoutURL(postLogoutRedirectURI: String? = nil, state: String? = nil) -> URL {
        ensureLoaded()
        var items: [(String, String)] = [("client_id", clientId)]
        if let idToken = current?.idToken { items.append(("id_token_hint", idToken)) }
        if let postLogoutRedirectURI { items.append(("post_logout_redirect_uri", postLogoutRedirectURI)) }
        if let state { items.append(("state", state)) }
        return URL(string: issuer + "/logout?" + FormEncoding.encode(items))!
    }

    /// Signs out (`signOut`) and also ends the hosted page's browser session (its cookie), opening the pool's logout
    /// address in the authentication browser. `postLogoutRedirectURI` (default: the redirect address) must be in the
    /// app's post-logout list, else the browser cannot come back; without one only the local sign-out happens.
    public func signOutWithHostedPage(postLogoutRedirectURI: String? = nil, everywhere: Bool = false,
                                      prefersEphemeralSession: Bool = false) async throws {
        let target = postLogoutRedirectURI ?? redirectURI
        let url = buildLogoutURL(postLogoutRedirectURI: target) // before signOut: it carries the id_token_hint
        await signOut(everywhere: everywhere)
        guard let target, !target.isEmpty, let webAuthenticator else { return }
        do {
            _ = try await webAuthenticator.authenticate(url: url, callbackURL: try callbackURL(target),
                                                        prefersEphemeralSession: prefersEphemeralSession)
        } catch let error as AppAuthError where error.code == "canceled" {
            // closed by the user: the local session is gone anyway
        }
    }
}

/// A listener registered with `onAuthStateChanged`; `cancel()` stops it.
public final class AuthStateSubscription: Sendable {
    private let task: Task<Void, Never>

    init(task: Task<Void, Never>) {
        self.task = task
    }

    /// Stops the listener. Keep the subscription while you need it and cancel it when done.
    public func cancel() {
        task.cancel()
    }
}
