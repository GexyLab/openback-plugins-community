import Foundation

// MARK: - Users and organizations

/// Two-step verification state of a user.
public struct MfaStatus: Codable, Equatable, Sendable {
    /// Whether TOTP is on.
    public var totp: Bool

    public init(totp: Bool = false) {
        self.totp = totp
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        totp = try c.decodeIfPresent(Bool.self, forKey: .totp) ?? false
    }
}

/// A sign-in provider linked to the user (Google, Microsoft, ...).
public struct LinkedProvider: Codable, Equatable, Sendable {
    /// The provider id (`uprov_...`).
    public var providerId: String
    /// The provider kind.
    public var kind: String?

    enum CodingKeys: String, CodingKey {
        case providerId = "provider_id"
        case kind
    }
}

/// A user of the pool, as the user sees themselves (`currentUser`, `me()`).
public struct PoolUser: Codable, Equatable, Sendable, Identifiable {
    /// The user id (`usr_...`), the tokens' `sub`.
    public var id: String
    /// The email address (nil for guests).
    public var email: String?
    /// Whether the email address is verified.
    public var emailVerified: Bool
    /// The display name ("" when unset).
    public var displayName: String
    /// The picture's address.
    public var photoUrl: String?
    /// The preferred language (`it`, `en` or nil).
    public var locale: String?
    /// The custom attributes.
    public var attributes: [String: JSONValue]
    /// True for a guest account.
    public var anonymous: Bool
    /// When the account was created (ISO 8601).
    public var createdAt: String?
    /// The last sign-in (ISO 8601).
    public var lastLoginAt: String?
    /// Two-step verification.
    public var mfa: MfaStatus
    /// The active organization (only in the answer of `me()`).
    public var orgId: String?
    /// The roles in the active organization (only in the answer of `me()`).
    public var roles: [String]?
    /// The linked providers (only in the answer of `me()`).
    public var providers: [LinkedProvider]?
    /// Whether the account has a password (only in the answer of `me()`).
    public var hasPassword: Bool?

    enum CodingKeys: String, CodingKey {
        case id, email, locale, attributes, anonymous, mfa, roles, providers
        case emailVerified = "email_verified"
        case displayName = "display_name"
        case photoUrl = "photo_url"
        case createdAt = "created_at"
        case lastLoginAt = "last_login_at"
        case orgId = "org_id"
        case hasPassword = "has_password"
    }

    public init(id: String, email: String? = nil, emailVerified: Bool = false, displayName: String = "",
                photoUrl: String? = nil, locale: String? = nil, attributes: [String: JSONValue] = [:],
                anonymous: Bool = false, createdAt: String? = nil, lastLoginAt: String? = nil,
                mfa: MfaStatus = MfaStatus(), orgId: String? = nil, roles: [String]? = nil,
                providers: [LinkedProvider]? = nil, hasPassword: Bool? = nil) {
        self.id = id
        self.email = email
        self.emailVerified = emailVerified
        self.displayName = displayName
        self.photoUrl = photoUrl
        self.locale = locale
        self.attributes = attributes
        self.anonymous = anonymous
        self.createdAt = createdAt
        self.lastLoginAt = lastLoginAt
        self.mfa = mfa
        self.orgId = orgId
        self.roles = roles
        self.providers = providers
        self.hasPassword = hasPassword
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        email = try c.decodeIfPresent(String.self, forKey: .email)
        emailVerified = try c.decodeIfPresent(Bool.self, forKey: .emailVerified) ?? false
        displayName = try c.decodeIfPresent(String.self, forKey: .displayName) ?? ""
        photoUrl = try c.decodeIfPresent(String.self, forKey: .photoUrl)
        locale = try c.decodeIfPresent(String.self, forKey: .locale)
        attributes = try c.decodeIfPresent([String: JSONValue].self, forKey: .attributes) ?? [:]
        anonymous = try c.decodeIfPresent(Bool.self, forKey: .anonymous) ?? false
        createdAt = try c.decodeIfPresent(String.self, forKey: .createdAt)
        lastLoginAt = try c.decodeIfPresent(String.self, forKey: .lastLoginAt)
        mfa = try c.decodeIfPresent(MfaStatus.self, forKey: .mfa) ?? MfaStatus()
        orgId = try c.decodeIfPresent(String.self, forKey: .orgId)
        roles = try c.decodeIfPresent([String].self, forKey: .roles)
        providers = try c.decodeIfPresent([LinkedProvider].self, forKey: .providers)
        hasPassword = try c.decodeIfPresent(Bool.self, forKey: .hasPassword)
    }
}

/// The organization of the session (B2B pools; nil in B2C pools).
public struct ActiveOrg: Codable, Equatable, Sendable, Identifiable {
    /// The organization id.
    public var id: String
    /// Its name.
    public var name: String?
    /// The user's roles in it.
    public var roles: [String]
    /// How many organizations the user may switch to (show a switcher when > 1).
    public var choices: Int

    public init(id: String, name: String? = nil, roles: [String] = [], choices: Int = 1) {
        self.id = id
        self.name = name
        self.roles = roles
        self.choices = choices
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decodeIfPresent(String.self, forKey: .name)
        roles = try c.decodeIfPresent([String].self, forKey: .roles) ?? []
        choices = try c.decodeIfPresent(Int.self, forKey: .choices) ?? 1
    }
}

/// The signed-in user and organization, or nobody.
public struct AuthState: Equatable, Sendable {
    /// The user, nil when signed out.
    public var user: PoolUser?
    /// The active organization (B2B).
    public var org: ActiveOrg?
    /// Whether a user is signed in.
    public var isSignedIn: Bool { user != nil }

    public init(user: PoolUser?, org: ActiveOrg?) {
        self.user = user
        self.org = org
    }

    /// Nobody signed in.
    public static let signedOut = AuthState(user: nil, org: nil)
}

// MARK: - Outcomes

/// The outcome of a sign-up or sign-in. Only `.ok` opens a session; the others tell the app how to continue.
public enum SignInOutcome: Equatable, Sendable {
    /// Signed in: the session is stored.
    case ok(user: PoolUser?, org: ActiveOrg?)
    /// The email address must be verified first (a code and a link were emailed): `verifyEmail`, then sign in.
    case verificationRequired
    /// A second factor is needed: `verifyMfa(mfaToken:code:)`.
    case mfaRequired(mfaToken: String)
    /// Two-step verification is mandatory and the user has none: `enrollMfa(mfaToken:)` + `confirmMfa(code:mfaToken:)`.
    case mfaEnrollRequired(mfaToken: String)
    /// A password set by an administrator must be changed: `changeForcedPassword(changeToken:newPassword:)`.
    case passwordChangeRequired(changeToken: String)

    /// The pool's status string.
    public var status: String {
        switch self {
        case .ok: return "ok"
        case .verificationRequired: return "verification_required"
        case .mfaRequired: return "mfa_required"
        case .mfaEnrollRequired: return "mfa_enroll_required"
        case .passwordChangeRequired: return "password_change_required"
        }
    }
}

/// A new TOTP secret to show to the user (as text and as a QR code of `otpauthURI`).
public struct MfaEnrollment: Codable, Equatable, Sendable {
    /// The base32 secret.
    public var secret: String
    /// The `otpauth://` address for authenticator apps.
    public var otpauthURI: String

    enum CodingKeys: String, CodingKey {
        case secret
        case otpauthURI = "otpauth_uri"
    }
}

/// The result of `confirmMfa`: the recovery codes (show them once) and, when enrolling during a sign-in, its outcome.
public struct MfaConfirmation: Equatable, Sendable {
    /// The one-time recovery codes.
    public var recoveryCodes: [String]
    /// The sign-in outcome (only when confirmed with an `mfaToken`).
    public var outcome: SignInOutcome?
}

// MARK: - Pool configuration

/// A sign-in provider of the pool.
public struct PoolProvider: Codable, Equatable, Sendable, Identifiable {
    /// The provider id: pass it as `provider` to the hosted sign-in.
    public var id: String
    /// The kind (`google`, `microsoft`, `apple`, `oidc`, ...).
    public var kind: String
    /// The label to show.
    public var label: String
    /// The hosted page's address that starts it.
    public var startURL: String?

    enum CodingKeys: String, CodingKey {
        case id, kind, label
        case startURL = "start_url"
    }
}

/// The public settings of the pool (`config()`).
public struct PoolConfig: Decodable, Equatable, Sendable {
    /// The pool's issuer.
    public var issuer: String
    /// `b2c` or `b2b`.
    public var mode: String
    /// The enabled sign-in methods.
    public var methods: JSONValue?
    /// The sign-up settings.
    public var signup: JSONValue?
    /// Whether the hosted sign-in page is on.
    public var hostedLogin: Bool
    /// The password policy.
    public var passwordPolicy: JSONValue?
    /// The two-step verification mode (`off`, `optional`, `required`).
    public var mfa: String?
    /// Whether users may create organizations (B2B).
    public var orgsSelfService: Bool
    /// The sign-in providers (through the hosted page).
    public var providers: [PoolProvider]
    /// `display_name`, `logo_url`, `primary_color`, `default_language`, `terms_url`, `privacy_url`.
    public var branding: [String: JSONValue]

    enum CodingKeys: String, CodingKey {
        case issuer, mode, methods, signup, mfa, orgs, providers, branding
        case hostedLogin = "hosted_login"
        case passwordPolicy = "password_policy"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        issuer = try c.decodeIfPresent(String.self, forKey: .issuer) ?? ""
        mode = try c.decodeIfPresent(String.self, forKey: .mode) ?? "b2c"
        methods = try c.decodeIfPresent(JSONValue.self, forKey: .methods)
        signup = try c.decodeIfPresent(JSONValue.self, forKey: .signup)
        hostedLogin = try c.decodeIfPresent(Bool.self, forKey: .hostedLogin) ?? true
        passwordPolicy = try c.decodeIfPresent(JSONValue.self, forKey: .passwordPolicy)
        mfa = try c.decodeIfPresent(String.self, forKey: .mfa)
        let orgs = try c.decodeIfPresent(JSONValue.self, forKey: .orgs)
        orgsSelfService = orgs?["self_service"]?.boolValue ?? false
        providers = try c.decodeIfPresent([PoolProvider].self, forKey: .providers) ?? []
        branding = try c.decodeIfPresent([String: JSONValue].self, forKey: .branding) ?? [:]
    }
}

// MARK: - Organizations (B2B)

/// One of the user's organizations.
public struct Organization: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    public var name: String
    /// The user's roles in it.
    public var roles: [String]
    public var disabled: Bool

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        roles = try c.decodeIfPresent([String].self, forKey: .roles) ?? []
        disabled = try c.decodeIfPresent(Bool.self, forKey: .disabled) ?? false
    }
}

/// The answer of `organizations()`.
public struct OrganizationList: Decodable, Equatable, Sendable {
    /// The user's organizations (empty in B2C pools).
    public var orgs: [Organization]
    /// The active organization's id.
    public var active: String?
}

/// A role of the pool's organizations.
public struct OrgRole: Codable, Equatable, Sendable {
    public var key: String
    public var label: String
}

/// A member of an organization.
public struct OrgMember: Decodable, Equatable, Sendable, Identifiable {
    public var userId: String
    public var email: String?
    public var displayName: String
    public var disabled: Bool
    public var roles: [String]
    public var createdAt: String?
    public var id: String { userId }

    enum CodingKeys: String, CodingKey {
        case email, disabled, roles
        case userId = "user_id"
        case displayName = "display_name"
        case createdAt = "created_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userId = try c.decode(String.self, forKey: .userId)
        email = try c.decodeIfPresent(String.self, forKey: .email)
        displayName = try c.decodeIfPresent(String.self, forKey: .displayName) ?? ""
        disabled = try c.decodeIfPresent(Bool.self, forKey: .disabled) ?? false
        roles = try c.decodeIfPresent([String].self, forKey: .roles) ?? []
        createdAt = try c.decodeIfPresent(String.self, forKey: .createdAt)
    }
}

/// A page of members (`members(orgId:)`).
public struct MemberPage: Decodable, Equatable, Sendable {
    public var items: [OrgMember]
    /// The total count, when the pool gives it.
    public var total: Int?
    /// The roles that can be granted.
    public var roles: [OrgRole]

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        items = try c.decodeIfPresent([OrgMember].self, forKey: .items) ?? []
        total = try c.decodeIfPresent(Int.self, forKey: .total)
        roles = try c.decodeIfPresent([OrgRole].self, forKey: .roles) ?? []
    }

    enum CodingKeys: String, CodingKey {
        case items, total, roles
    }
}

/// The answer of `addMember`.
public struct AddedMember: Decodable, Equatable, Sendable {
    public var userId: String
    public var email: String?
    public var roles: [String]
    /// Whether a new account was created.
    public var created: Bool
    /// The temporary password of a new account (shown once; to be changed at the first sign-in).
    public var temporaryPassword: String?

    enum CodingKeys: String, CodingKey {
        case email, roles, created
        case userId = "user_id"
        case temporaryPassword = "temporary_password"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userId = try c.decode(String.self, forKey: .userId)
        email = try c.decodeIfPresent(String.self, forKey: .email)
        roles = try c.decodeIfPresent([String].self, forKey: .roles) ?? []
        created = try c.decodeIfPresent(Bool.self, forKey: .created) ?? false
        temporaryPassword = try c.decodeIfPresent(String.self, forKey: .temporaryPassword)
    }
}

// MARK: - Hosted sign-in

/// Options of the hosted sign-in (`<issuer>/authorize`).
public struct AuthorizationOptions: Sendable {
    /// Go straight to a provider (`uprov_...`, see `config().providers`).
    public var provider: String?
    /// B2B: the organization to sign in to.
    public var orgId: String?
    /// `none` or `login`.
    public var prompt: String?
    /// `signup` opens the sign-up form.
    public var screenHint: String?
    /// Prefills the email.
    public var loginHint: String?
    /// Maximum age of the browser session, in seconds.
    public var maxAge: Int?
    /// The scopes (default `openid profile email`).
    public var scope: String
    /// `it` or `en`.
    public var uiLocales: String?

    public init(provider: String? = nil, orgId: String? = nil, prompt: String? = nil, screenHint: String? = nil,
                loginHint: String? = nil, maxAge: Int? = nil, scope: String = "openid profile email",
                uiLocales: String? = nil) {
        self.provider = provider
        self.orgId = orgId
        self.prompt = prompt
        self.screenHint = screenHint
        self.loginHint = loginHint
        self.maxAge = maxAge
        self.scope = scope
        self.uiLocales = uiLocales
    }
}

/// A hosted sign-in in progress. The SDK stores it until the callback.
public struct AuthorizationRequest: Codable, Equatable, Sendable {
    /// The `<issuer>/authorize` address to open.
    public var url: URL
    /// The `state` the callback must carry.
    public var state: String
    /// The `nonce` the ID token must carry.
    public var nonce: String
    /// The PKCE code verifier (secret: never log it).
    public var codeVerifier: String
    /// The registered redirect address.
    public var redirectURI: String
}

// MARK: - Wire formats

/// A sign-in outcome or a token answer.
struct TokenWire: Decodable {
    var status: String?
    var accessToken: String?
    var refreshToken: String?
    var idToken: String?
    var expiresIn: Double?
    var user: PoolUser?
    var org: ActiveOrg?
    var mfaToken: String?
    var changeToken: String?
    var recoveryCodes: [String]?

    enum CodingKeys: String, CodingKey {
        case status, user, org
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case idToken = "id_token"
        case expiresIn = "expires_in"
        case mfaToken = "mfa_token"
        case changeToken = "change_token"
        case recoveryCodes = "recovery_codes"
    }
}

struct UserWire: Decodable {
    var user: PoolUser?
}

struct RolesWire: Decodable {
    var roles: [String]?
}

struct RecoveryWire: Decodable {
    var recoveryCodes: [String]?

    enum CodingKeys: String, CodingKey {
        case recoveryCodes = "recovery_codes"
    }
}

/// The stored session: `{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}`.
struct StoredSession: Codable, Equatable {
    var accessToken: String
    var refreshToken: String
    var idToken: String?
    var expiresAt: Int64
    var user: PoolUser?
    var org: ActiveOrg?

    enum CodingKeys: String, CodingKey {
        case accessToken, refreshToken, idToken, expiresAt, user, org
    }

    init(accessToken: String, refreshToken: String, idToken: String?, expiresAt: Int64, user: PoolUser?, org: ActiveOrg?) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.expiresAt = expiresAt
        self.user = user
        self.org = org
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        accessToken = try c.decode(String.self, forKey: .accessToken)
        refreshToken = try c.decode(String.self, forKey: .refreshToken)
        idToken = try c.decodeIfPresent(String.self, forKey: .idToken)
        expiresAt = Int64(try c.decodeIfPresent(Double.self, forKey: .expiresAt) ?? 0)
        user = try c.decodeIfPresent(PoolUser.self, forKey: .user)
        org = try c.decodeIfPresent(ActiveOrg.self, forKey: .org)
    }

    // Writes every key, with null for the missing ones (same shape as the other SDKs).
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(accessToken, forKey: .accessToken)
        try c.encode(refreshToken, forKey: .refreshToken)
        if let idToken { try c.encode(idToken, forKey: .idToken) } else { try c.encodeNil(forKey: .idToken) }
        try c.encode(expiresAt, forKey: .expiresAt)
        if let user { try c.encode(user, forKey: .user) } else { try c.encodeNil(forKey: .user) }
        if let org { try c.encode(org, forKey: .org) } else { try c.encodeNil(forKey: .org) }
    }
}
