// The values the SDK returns. Every model keeps the pool's raw JSON in `json` for fields added later.

String? _str(Object? v) => v is String ? v : null;
bool _bool(Object? v) => v == true;
int? _int(Object? v) => v is int ? v : (v is num ? v.toInt() : null);
List<String> _strings(Object? v) => v is List ? v.map((e) => e.toString()).toList(growable: false) : const <String>[];
Map<String, dynamic> _map(Object? v) => v is Map ? Map<String, dynamic>.from(v) : <String, dynamic>{};
DateTime? _date(Object? v) => v is String ? DateTime.tryParse(v) : null;

/// A user of the pool, as the user sees themselves (`currentUser`, `me()`).
class PoolUser {
  /// Builds a user from the pool's JSON.
  PoolUser.fromJson(Map<String, dynamic> json)
      : json = Map.unmodifiable(json),
        id = _str(json['id']) ?? '',
        email = _str(json['email']),
        emailVerified = _bool(json['email_verified']),
        displayName = _str(json['display_name']) ?? '',
        photoUrl = _str(json['photo_url']),
        locale = _str(json['locale']),
        attributes = Map.unmodifiable(_map(json['attributes'])),
        anonymous = _bool(json['anonymous']),
        createdAt = _date(json['created_at']),
        lastLoginAt = _date(json['last_login_at']),
        mfaTotp = _bool(_map(json['mfa'])['totp']),
        orgId = _str(json['org_id']),
        roles = _strings(json['roles']),
        providers = (json['providers'] is List ? json['providers'] as List : const [])
            .whereType<Map>()
            .map((p) => LinkedProvider(_str(p['provider_id']) ?? '', _str(p['kind'])))
            .toList(growable: false),
        hasPassword = json['has_password'] is bool ? json['has_password'] as bool : null;

  /// The raw JSON.
  final Map<String, dynamic> json;

  /// The user id (`usr_...`), the `sub` of the tokens.
  final String id;

  /// The email address (null for guests).
  final String? email;

  /// Whether the email address is verified.
  final bool emailVerified;

  /// The display name ('' when unset).
  final String displayName;

  /// The picture's address.
  final String? photoUrl;

  /// The preferred language (`it`, `en` or null).
  final String? locale;

  /// The custom attributes.
  final Map<String, dynamic> attributes;

  /// True for a guest account (`signInAnonymously`).
  final bool anonymous;

  /// When the account was created.
  final DateTime? createdAt;

  /// The last sign-in.
  final DateTime? lastLoginAt;

  /// Whether two-step verification (TOTP) is on.
  final bool mfaTotp;

  /// The active organization (only in the answer of `me()`).
  final String? orgId;

  /// The roles in the active organization (only in the answer of `me()`).
  final List<String> roles;

  /// The linked sign-in providers (only in the answer of `me()`).
  final List<LinkedProvider> providers;

  /// Whether the account has a password (only in the answer of `me()`).
  final bool? hasPassword;

  /// The raw JSON (what the SDK stores).
  Map<String, dynamic> toJson() => json;

  @override
  String toString() => 'PoolUser($id)';
}

/// A sign-in provider linked to the user (Google, Microsoft, ...).
class LinkedProvider {
  /// Creates a provider link.
  const LinkedProvider(this.providerId, this.kind);

  /// The provider id (`uprov_...`).
  final String providerId;

  /// The provider kind (`google`, `microsoft`, `oidc`, ...).
  final String? kind;
}

/// The organization of the session (B2B pools; always null in B2C pools).
class ActiveOrg {
  /// Builds it from the pool's JSON.
  ActiveOrg.fromJson(Map<String, dynamic> json)
      : json = Map.unmodifiable(json),
        id = _str(json['id']) ?? '',
        name = _str(json['name']),
        roles = _strings(json['roles']),
        choices = _int(json['choices']) ?? 1;

  /// The raw JSON.
  final Map<String, dynamic> json;

  /// The organization id.
  final String id;

  /// Its name.
  final String? name;

  /// The user's roles in it.
  final List<String> roles;

  /// How many organizations the user may switch to (show a switcher when > 1).
  final int choices;

  /// The raw JSON.
  Map<String, dynamic> toJson() => json;
}

/// The signed-in user and organization, or nobody.
class AuthState {
  /// Creates a state.
  const AuthState(this.user, this.org);

  /// Nobody signed in.
  static const AuthState signedOut = AuthState(null, null);

  /// The user, null when signed out.
  final PoolUser? user;

  /// The active organization (B2B), null otherwise.
  final ActiveOrg? org;

  /// Whether a user is signed in.
  bool get isSignedIn => user != null;
}

/// The outcome of a sign-up or sign-in. Only [SignInOk] opens a session; the others tell the app how to continue.
///
/// ```dart
/// switch (await auth.signInWithPassword(email: e, password: p)) {
///   case SignInOk(:final user): ...
///   case MfaRequired(:final mfaToken): ...           // auth.verifyMfa(mfaToken: mfaToken, code: code)
///   case MfaEnrollRequired(:final mfaToken): ...     // auth.enrollMfa(mfaToken: ...) + auth.confirmMfa(...)
///   case PasswordChangeRequired(:final changeToken): // auth.changeForcedPassword(...)
///   case VerificationRequired(): ...                 // a code and a link were emailed
/// }
/// ```
sealed class SignInOutcome {
  /// Creates an outcome.
  const SignInOutcome(this.json);

  /// The raw JSON of the answer, WITHOUT the tokens.
  final Map<String, dynamic> json;

  /// The pool's status string (`ok`, `verification_required`, `mfa_required`, `mfa_enroll_required`,
  /// `password_change_required`).
  String get status;

  /// Builds the outcome of an answer (tokens removed from [json]).
  static SignInOutcome fromJson(Map<String, dynamic> json) {
    final safe = Map<String, dynamic>.from(json)
      ..remove('access_token')
      ..remove('refresh_token')
      ..remove('id_token');
    switch (json['status']) {
      case 'ok':
        final user = json['user'] is Map ? PoolUser.fromJson(_map(json['user'])) : null;
        final org = json['org'] is Map ? ActiveOrg.fromJson(_map(json['org'])) : null;
        return SignInOk(safe, user, org, _strings(json['recovery_codes']));
      case 'verification_required':
        return VerificationRequired(safe);
      case 'mfa_required':
        return MfaRequired(safe, _str(json['mfa_token']) ?? '');
      case 'mfa_enroll_required':
        return MfaEnrollRequired(safe, _str(json['mfa_token']) ?? '');
      case 'password_change_required':
        return PasswordChangeRequired(safe, _str(json['change_token']) ?? '');
      default:
        throw FormatException('Unknown sign-in status: ${json['status']}');
    }
  }
}

/// Signed in: the session is stored and `authStateChanges` emitted the user.
final class SignInOk extends SignInOutcome {
  /// Creates the outcome.
  const SignInOk(super.json, this.user, this.org, [this.recoveryCodes = const []]);

  /// The signed-in user.
  final PoolUser? user;

  /// The active organization (B2B).
  final ActiveOrg? org;

  /// The recovery codes, when the sign-in finished a two-step verification enrollment (show them once).
  final List<String> recoveryCodes;

  @override
  String get status => 'ok';
}

/// The email address must be verified first: the pool emailed a code and a link (`verifyEmail`).
final class VerificationRequired extends SignInOutcome {
  /// Creates the outcome.
  const VerificationRequired(super.json);

  @override
  String get status => 'verification_required';
}

/// A second factor is needed: call `verifyMfa(mfaToken: ..., code: ...)` with a TOTP or recovery code.
final class MfaRequired extends SignInOutcome {
  /// Creates the outcome.
  const MfaRequired(super.json, this.mfaToken);

  /// The short-lived token of this sign-in.
  final String mfaToken;

  @override
  String get status => 'mfa_required';
}

/// Two-step verification is mandatory and the user has none: `enrollMfa(mfaToken: ...)`, then
/// `confirmMfa(code, mfaToken: ...)`.
final class MfaEnrollRequired extends SignInOutcome {
  /// Creates the outcome.
  const MfaEnrollRequired(super.json, this.mfaToken);

  /// The short-lived token of this sign-in.
  final String mfaToken;

  @override
  String get status => 'mfa_enroll_required';
}

/// A password set by an administrator must be changed: `changeForcedPassword(changeToken: ..., newPassword: ...)`,
/// then sign in again.
final class PasswordChangeRequired extends SignInOutcome {
  /// Creates the outcome.
  const PasswordChangeRequired(super.json, this.changeToken);

  /// The token that allows the change.
  final String changeToken;

  @override
  String get status => 'password_change_required';
}

/// A new TOTP secret to show to the user (as text and as a QR code of [otpauthUri]).
class MfaEnrollment {
  /// Builds it from the pool's JSON.
  MfaEnrollment.fromJson(Map<String, dynamic> json)
      : secret = _str(json['secret']) ?? '',
        otpauthUri = _str(json['otpauth_uri']) ?? '';

  /// The base32 secret.
  final String secret;

  /// The `otpauth://` address for authenticator apps.
  final String otpauthUri;
}

/// The result of `confirmMfa`: the recovery codes (show them once) and, when enrolling during a sign-in, its outcome.
class MfaConfirmation {
  /// Creates it.
  const MfaConfirmation(this.recoveryCodes, this.outcome);

  /// The one-time recovery codes.
  final List<String> recoveryCodes;

  /// The sign-in outcome (only when confirmed with an `mfaToken`).
  final SignInOutcome? outcome;
}

/// A sign-in provider of the pool (`config().providers`).
class PoolProvider {
  /// Builds it from the pool's JSON.
  PoolProvider.fromJson(Map<String, dynamic> json)
      : id = _str(json['id']) ?? '',
        kind = _str(json['kind']) ?? '',
        label = _str(json['label']) ?? '',
        startUrl = _str(json['start_url']);

  /// The provider id: pass it as `provider` to `signInWithHostedPage`.
  final String id;

  /// The kind (`google`, `microsoft`, `apple`, `oidc`, ...).
  final String kind;

  /// The label to show.
  final String label;

  /// The hosted page's address that starts it.
  final String? startUrl;
}

/// The public settings of the pool (`config()`).
class PoolConfig {
  /// Builds it from the pool's JSON.
  PoolConfig.fromJson(Map<String, dynamic> json)
      : json = Map.unmodifiable(json),
        issuer = _str(json['issuer']) ?? '',
        mode = _str(json['mode']) ?? 'b2c',
        methods = _map(json['methods']),
        signup = json['signup'],
        hostedLogin = json['hosted_login'] != false,
        passwordPolicy = _map(json['password_policy']),
        mfa = _str(json['mfa']),
        orgsSelfService = _bool(_map(json['orgs'])['self_service']),
        providers = (json['providers'] is List ? json['providers'] as List : const [])
            .whereType<Map>()
            .map((p) => PoolProvider.fromJson(_map(p)))
            .toList(growable: false),
        branding = _map(json['branding']);

  /// The raw JSON.
  final Map<String, dynamic> json;

  /// The pool's issuer.
  final String issuer;

  /// `b2c` or `b2b`.
  final String mode;

  /// The enabled sign-in methods.
  final Map<String, dynamic> methods;

  /// The sign-up settings.
  final Object? signup;

  /// Whether the hosted sign-in page is on.
  final bool hostedLogin;

  /// The password policy (minimum length, character classes).
  final Map<String, dynamic> passwordPolicy;

  /// The two-step verification mode (`off`, `optional`, `required`).
  final String? mfa;

  /// Whether users may create organizations (B2B).
  final bool orgsSelfService;

  /// The sign-in providers (through the hosted page).
  final List<PoolProvider> providers;

  /// `display_name`, `logo_url`, `primary_color`, `default_language`, `terms_url`, `privacy_url`.
  final Map<String, dynamic> branding;
}

/// One of the user's organizations (B2B).
class Organization {
  /// Builds it from the pool's JSON.
  Organization.fromJson(Map<String, dynamic> json)
      : id = _str(json['id']) ?? '',
        name = _str(json['name']) ?? '',
        roles = _strings(json['roles']),
        disabled = _bool(json['disabled']);

  /// The organization id.
  final String id;

  /// Its name.
  final String name;

  /// The user's roles in it.
  final List<String> roles;

  /// Whether it is disabled.
  final bool disabled;
}

/// The answer of `organizations()`.
class OrganizationList {
  /// Builds it from the pool's JSON.
  OrganizationList.fromJson(Map<String, dynamic> json)
      : orgs = (json['orgs'] is List ? json['orgs'] as List : const [])
            .whereType<Map>()
            .map((o) => Organization.fromJson(_map(o)))
            .toList(growable: false),
        active = _str(json['active']);

  /// The user's organizations (empty in B2C pools).
  final List<Organization> orgs;

  /// The active organization's id.
  final String? active;
}

/// A role of the pool's organizations.
class OrgRole {
  /// Creates a role.
  const OrgRole(this.key, this.label);

  /// The role key (`owner`, `admin`, `member`, ...).
  final String key;

  /// Its label.
  final String label;
}

/// A member of an organization.
class OrgMember {
  /// Builds it from the pool's JSON.
  OrgMember.fromJson(Map<String, dynamic> json)
      : userId = _str(json['user_id']) ?? '',
        email = _str(json['email']),
        displayName = _str(json['display_name']) ?? '',
        disabled = _bool(json['disabled']),
        roles = _strings(json['roles']),
        createdAt = _date(json['created_at']);

  /// The user id.
  final String userId;

  /// The email address.
  final String? email;

  /// The display name.
  final String displayName;

  /// Whether the account is disabled.
  final bool disabled;

  /// The roles in the organization.
  final List<String> roles;

  /// When the user joined.
  final DateTime? createdAt;
}

/// A page of members (`members()`).
class MemberPage {
  /// Builds it from the pool's JSON.
  MemberPage.fromJson(Map<String, dynamic> json)
      : items = (json['items'] is List ? json['items'] as List : const [])
            .whereType<Map>()
            .map((m) => OrgMember.fromJson(_map(m)))
            .toList(growable: false),
        total = _int(json['total']),
        roles = (json['roles'] is List ? json['roles'] as List : const [])
            .whereType<Map>()
            .map((r) => OrgRole(_str(r['key']) ?? '', _str(r['label']) ?? ''))
            .toList(growable: false);

  /// The members of this page.
  final List<OrgMember> items;

  /// The total count, when the pool gives it.
  final int? total;

  /// The roles that can be granted.
  final List<OrgRole> roles;
}

/// The answer of `addMember()`.
class AddedMember {
  /// Builds it from the pool's JSON.
  AddedMember.fromJson(Map<String, dynamic> json)
      : userId = _str(json['user_id']) ?? '',
        email = _str(json['email']),
        roles = _strings(json['roles']),
        created = _bool(json['created']),
        temporaryPassword = _str(json['temporary_password']);

  /// The user id.
  final String userId;

  /// The email address.
  final String? email;

  /// The granted roles.
  final List<String> roles;

  /// Whether a new account was created.
  final bool created;

  /// The temporary password of a new account (shown once; the user must change it at the first sign-in).
  final String? temporaryPassword;
}

/// A hosted sign-in in progress (`buildAuthorizationRequest`). The SDK persists it until the callback.
class AuthorizationRequest {
  /// Creates it.
  const AuthorizationRequest({
    required this.url,
    required this.state,
    required this.nonce,
    required this.codeVerifier,
    required this.redirectUri,
  });

  /// The `<issuer>/authorize` address to open in a browser.
  final Uri url;

  /// The `state` the callback must carry.
  final String state;

  /// The `nonce` the ID token must carry.
  final String nonce;

  /// The PKCE code verifier (secret: never log it).
  final String codeVerifier;

  /// The redirect address (registered in the pool).
  final String redirectUri;

  /// What the SDK stores until the callback.
  Map<String, dynamic> toJson() => {
        'url': url.toString(),
        'state': state,
        'nonce': nonce,
        'codeVerifier': codeVerifier,
        'redirectUri': redirectUri,
      };

  /// Reads a stored request.
  static AuthorizationRequest? fromJson(Object? json) {
    if (json is! Map) return null;
    final state = _str(json['state']);
    final verifier = _str(json['codeVerifier']);
    final redirect = _str(json['redirectUri']);
    if (state == null || verifier == null || redirect == null) return null;
    return AuthorizationRequest(
      url: Uri.parse(_str(json['url']) ?? ''),
      state: state,
      nonce: _str(json['nonce']) ?? '',
      codeVerifier: verifier,
      redirectUri: redirect,
    );
  }
}
