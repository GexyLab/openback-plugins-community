import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:http/http.dart' as http;

import 'authorized_client.dart';
import 'errors.dart';
import 'jwt.dart';
import 'models.dart';
import 'pkce.dart';
import 'storage.dart';

/// Opens [url] in the platform's authentication browser and completes with the full callback address.
///
/// The default uses `flutter_web_auth_2` (ASWebAuthenticationSession on iOS/macOS, Custom Tabs on Android, a popup
/// on the web, a local loopback server on Windows/Linux). Tests and custom browsers pass their own.
typedef WebAuthenticator = Future<String> Function({
  required String url,
  required String callbackUrlScheme,
  required bool preferEphemeral,
});

Future<String> _flutterWebAuth2({
  required String url,
  required String callbackUrlScheme,
  required bool preferEphemeral,
}) {
  return FlutterWebAuth2.authenticate(
    url: url,
    callbackUrlScheme: callbackUrlScheme,
    options: FlutterWebAuth2Options(preferEphemeral: preferEphemeral),
  );
}

const AppAuthException _notSignedIn = AppAuthException(401, 'not_signed_in', 'Not signed in');

Map<String, dynamic> _asMap(Object? value) => value is Map ? Map<String, dynamic>.from(value) : <String, dynamic>{};

List<String> _asStrings(Object? value) =>
    value is List ? value.map((e) => e.toString()).toList(growable: false) : const <String>[];

/// The stored session: `{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}`.
class _Session {
  const _Session({
    required this.accessToken,
    required this.refreshToken,
    required this.idToken,
    required this.expiresAt,
    required this.user,
    required this.org,
  });

  final String accessToken;
  final String refreshToken;
  final String? idToken;
  final int expiresAt;
  final Map<String, dynamic>? user;
  final Map<String, dynamic>? org;

  _Session withUser(Map<String, dynamic>? value) => _Session(
        accessToken: accessToken,
        refreshToken: refreshToken,
        idToken: idToken,
        expiresAt: expiresAt,
        user: value,
        org: org,
      );

  Map<String, dynamic> toJson() => {
        'accessToken': accessToken,
        'refreshToken': refreshToken,
        'idToken': idToken,
        'expiresAt': expiresAt,
        'user': user,
        'org': org,
      };

  static _Session? fromJson(Object? json) {
    if (json is! Map) return null;
    final access = json['accessToken'];
    final refresh = json['refreshToken'];
    if (access is! String || refresh is! String || refresh.isEmpty) return null;
    final expires = json['expiresAt'];
    return _Session(
      accessToken: access,
      refreshToken: refresh,
      idToken: json['idToken'] is String ? json['idToken'] as String : null,
      expiresAt: expires is num ? expires.toInt() : 0,
      user: json['user'] is Map ? _asMap(json['user']) : null,
      org: json['org'] is Map ? _asMap(json['org']) : null,
    );
  }
}

/// The client of an OpenBack user pool (users-service, "App authenticator").
///
/// ```dart
/// final auth = OpenBackAppAuth(
///   issuer: 'https://api.example.com/gateway/shop/auth/main',
///   clientId: 'uapp_...',
///   redirectUri: 'com.example.app:/oauth2redirect',
/// );
/// await auth.initialize();
/// final outcome = await auth.signInWithPassword(email: email, password: password);
/// ```
///
/// Two ways to sign users in, freely mixed: your own screens ([signUp], [signInWithPassword], [signInWithEmailCode],
/// [signInAnonymously], [verifyMfa]) call the pool's JSON API; [signInWithHostedPage] opens the pool's hosted page
/// (OpenID Connect, authorization code + PKCE) for social providers and the pool's own forms.
///
/// The session is kept in a [TokenStorage] ([SecureTokenStorage] by default), the access token is renewed one minute
/// before it expires (one renewal at a time: refresh tokens rotate at every use) and [authStateChanges] tells the app
/// when the user changes.
class OpenBackAppAuth {
  /// Creates a client of the pool at [issuer] (trailing slashes are removed) for the app [clientId] (`uapp_...`).
  ///
  /// [redirectUri] is the app's registered redirect address, needed by the hosted sign-in (e.g.
  /// `com.example.app:/oauth2redirect`, `http://localhost:43823/callback` on Windows/Linux, the callback page's
  /// address on the web). [callbackUrlScheme] overrides the scheme handed to `flutter_web_auth_2` (default: derived
  /// from [redirectUri]). [storage] defaults to [SecureTokenStorage]; [storageKey] to `openback.auth.<clientId>`.
  OpenBackAppAuth({
    required String issuer,
    required this.clientId,
    this.redirectUri,
    TokenStorage? storage,
    String? storageKey,
    http.Client? httpClient,
    this.callbackUrlScheme,
    WebAuthenticator? webAuthenticator,
    DateTime Function()? clock,
  })  : issuer = issuer.trim().replaceFirst(RegExp(r'/+$'), ''),
        storageKey = storageKey ?? 'openback.auth.$clientId',
        _storage = storage ?? SecureTokenStorage(),
        _http = httpClient ?? http.Client(),
        _ownsHttp = httpClient == null,
        _webAuth = webAuthenticator ?? _flutterWebAuth2,
        _now = clock ?? DateTime.now {
    if (this.issuer.isEmpty || clientId.isEmpty) {
      throw ArgumentError('OpenBackAppAuth: issuer and clientId are required');
    }
  }

  static const String _api = '/api/v1';
  static const Duration _skew = Duration(seconds: 60);

  /// The pool's address (no trailing slash).
  final String issuer;

  /// The app's client ID.
  final String clientId;

  /// The app's redirect address for the hosted sign-in.
  final String? redirectUri;

  /// The callback scheme passed to `flutter_web_auth_2` (null: derived from the redirect address).
  final String? callbackUrlScheme;

  /// The storage key of the session.
  final String storageKey;

  final TokenStorage _storage;
  final http.Client _http;
  final bool _ownsHttp;
  final WebAuthenticator _webAuth;
  final DateTime Function() _now;
  final StreamController<AuthState> _changes = StreamController<AuthState>.broadcast();

  _Session? _session;
  AuthState _state = AuthState.signedOut;
  Future<void>? _loading;
  bool _written = false;
  Future<String>? _refreshing;

  String get _pendingKey => '$storageKey.pkce';

  // --- state -----------------------------------------------------------------------------------------------------

  /// Loads the stored session. Call it once at startup before reading [currentUser] (every other method waits for it).
  Future<void> initialize() => _ensureLoaded();

  Future<void> _ensureLoaded() => _loading ??= _load();

  Future<void> _load() async {
    _Session? loaded;
    try {
      final raw = await _storage.read(storageKey);
      if (raw != null && raw.isNotEmpty) loaded = _Session.fromJson(jsonDecode(raw));
    } catch (_) {
      loaded = null; // unreadable storage: start signed out
    }
    if (_written) return; // a sign-in finished meanwhile: it wins
    _session = loaded;
    _state = _stateOf(loaded);
  }

  Future<void> _save(_Session? next) async {
    _written = true;
    _session = next;
    _state = _stateOf(next);
    try {
      if (next != null && next.refreshToken.isNotEmpty) {
        await _storage.write(storageKey, jsonEncode(next.toJson()));
      } else {
        await _storage.delete(storageKey);
      }
    } finally {
      if (!_changes.isClosed) _changes.add(_state);
    }
  }

  AuthState _stateOf(_Session? s) {
    if (s == null) return AuthState.signedOut;
    final user = s.user ?? _userFromClaims(s.accessToken);
    final org = s.org;
    return AuthState(user == null ? null : PoolUser.fromJson(user), org == null ? null : ActiveOrg.fromJson(org));
  }

  // Until /me answers (hosted sign-in), the user known from the access token.
  Map<String, dynamic>? _userFromClaims(String token) {
    final claims = decodeJwtPayload(token);
    if (claims == null || claims['sub'] is! String) return null;
    return {
      'id': claims['sub'],
      'email': claims['email'],
      'email_verified': claims['email_verified'] == true,
      'display_name': claims['name'] is String ? claims['name'] : '',
      'anonymous': claims['anon'] == true,
      'attributes': claims['attr'] is Map ? claims['attr'] : <String, dynamic>{},
    };
  }

  /// The signed-in user (null when signed out or before [initialize]).
  PoolUser? get currentUser => _state.user;

  /// The active organization (B2B pools; null in B2C pools).
  ActiveOrg? get currentOrg => _state.org;

  /// The current state (user and organization).
  AuthState get authState => _state;

  /// Whether a session is stored.
  bool get isSignedIn => _session != null;

  /// The access token's claims, decoded but NOT verified (for display: roles, permissions, org_id).
  Map<String, dynamic>? get accessTokenClaims => decodeJwtPayload(_session?.accessToken);

  /// The state now (once loaded) and at every change: sign-in, renewal, profile update, sign-out.
  Stream<AuthState> get authStateChanges {
    late final StreamController<AuthState> controller;
    StreamSubscription<AuthState>? subscription;
    controller = StreamController<AuthState>(
      onListen: () {
        subscription = _changes.stream.listen(controller.add, onDone: controller.close);
        _ensureLoaded().then((_) {
          if (!controller.isClosed) controller.add(_state);
        });
      },
      onCancel: () async {
        await subscription?.cancel();
      },
    );
    return controller.stream;
  }

  /// Calls [listener] now (once loaded) and at every change; call the returned function to stop.
  void Function() onAuthStateChanged(void Function(PoolUser? user, ActiveOrg? org) listener) {
    final subscription = authStateChanges.listen((s) => listener(s.user, s.org));
    return () {
      unawaited(subscription.cancel());
    };
  }

  /// Releases the client (closes [authStateChanges] and the HTTP client it created).
  Future<void> dispose() async {
    await _changes.close();
    if (_ownsHttp) _http.close();
  }

  // --- HTTP ------------------------------------------------------------------------------------------------------

  Future<Object?> _call(String method, String path, {Object? body, bool auth = false, String? bearer}) async {
    await _ensureLoaded();
    final headers = <String, String>{'X-Client-Id': clientId, 'Accept': 'application/json'};
    final token = bearer ?? (auth ? await getAccessToken() : null);
    if (token != null) headers['Authorization'] = 'Bearer $token';
    final request = http.Request(method, Uri.parse('$issuer$_api$path'))..headers.addAll(headers);
    if (body != null) {
      request.headers['Content-Type'] = 'application/json';
      request.body = jsonEncode(body);
    }
    final http.Response res;
    try {
      res = await http.Response.fromStream(await _http.send(request));
    } catch (e) {
      throw AppAuthException(0, 'network_error', 'The user pool could not be reached', cause: e);
    }
    Object? data;
    if (res.bodyBytes.isNotEmpty) {
      try {
        data = jsonDecode(utf8.decode(res.bodyBytes));
      } catch (_) {
        data = null;
      }
    }
    if (res.statusCode < 200 || res.statusCode >= 300) {
      final error = AppAuthException.fromApi(res.statusCode, data, res.reasonPhrase);
      if (error.status == 401 &&
          (error.code == 'invalid_refresh_token' || (token != null && error.code.startsWith('token_')))) {
        await _save(null); // the session is dead: signed out
      }
      throw error;
    }
    return data;
  }

  Future<Map<String, dynamic>> _json(String method, String path, {Object? body, bool auth = false, String? bearer}) async =>
      _asMap(await _call(method, path, body: body, auth: auth, bearer: bearer));

  Future<Map<String, dynamic>> _tokenEndpoint(Map<String, String> form) async {
    final http.Response res;
    try {
      res = await _http.post(Uri.parse('$issuer/token'), headers: {'Accept': 'application/json'}, body: form);
    } catch (e) {
      throw AppAuthException(0, 'network_error', 'The user pool could not be reached', cause: e);
    }
    Object? data;
    try {
      data = jsonDecode(utf8.decode(res.bodyBytes));
    } catch (_) {
      data = null;
    }
    if (res.statusCode < 200 || res.statusCode >= 300) throw AppAuthException.fromOAuth(res.statusCode, data);
    return _asMap(data);
  }

  // An outcome of a sign-up or sign-in: the session is kept only when "ok".
  Future<SignInOutcome> _outcome(Map<String, dynamic> data) async {
    final SignInOutcome outcome;
    try {
      outcome = SignInOutcome.fromJson(data);
    } on FormatException catch (e) {
      throw AppAuthException(0, 'unexpected_response', e.message);
    }
    if (outcome is SignInOk && data['access_token'] is String) {
      await _storeTokens(data, user: data['user'] is Map ? _asMap(data['user']) : null, newSignIn: true);
    }
    return outcome;
  }

  Future<void> _storeTokens(Map<String, dynamic> data, {Map<String, dynamic>? user, bool newSignIn = false}) {
    final prev = newSignIn ? null : _session;
    final expiresIn = data['expires_in'] is num ? (data['expires_in'] as num).toInt() : 900;
    return _save(_Session(
      accessToken: data['access_token'] as String,
      refreshToken: data['refresh_token'] is String ? data['refresh_token'] as String : (prev?.refreshToken ?? ''),
      idToken: data['id_token'] is String ? data['id_token'] as String : prev?.idToken,
      expiresAt: _now().millisecondsSinceEpoch + expiresIn * 1000,
      user: user ?? prev?.user,
      org: data['org'] is Map ? _asMap(data['org']) : null,
    ));
  }

  Future<void> _setUser(Map<String, dynamic> user) async {
    final s = _session;
    if (s == null) return;
    final known = s.user ?? _userFromClaims(s.accessToken);
    if (known != null && known['id'] != null && user['id'] != null && known['id'] != user['id']) return;
    await _save(s.withUser(user));
  }

  Future<void> _patchUser(void Function(Map<String, dynamic> user) change) async {
    final s = _session;
    final user = s?.user;
    if (s == null || user == null) return;
    final copy = Map<String, dynamic>.from(user);
    change(copy);
    await _save(s.withUser(copy));
  }

  // --- tokens ----------------------------------------------------------------------------------------------------

  bool _fresh(_Session s) => s.expiresAt - _now().millisecondsSinceEpoch > _skew.inMilliseconds;

  /// A valid access token: the stored one if it expires in more than 60 s, else a renewed one.
  /// Throws [AppAuthException] `not_signed_in` when signed out.
  Future<String> getAccessToken() async {
    await _ensureLoaded();
    final s = _session;
    if (s == null) throw _notSignedIn;
    if (_fresh(s)) return s.accessToken;
    return refresh();
  }

  /// Renews the tokens now (optionally for the organization [orgId]). One renewal at a time: concurrent callers
  /// share it. A network failure is surfaced and never retried automatically (the refresh token rotates); the next
  /// call tries again with the stored token. A refused refresh token clears the session.
  Future<String> refresh({String? orgId}) async {
    await _ensureLoaded();
    for (;;) {
      final running = _refreshing;
      if (running == null) break;
      if (orgId == null) return running;
      try {
        await running;
      } catch (_) {
        // its caller handles it
      }
    }
    return _exclusive(() async {
      final s = _session;
      if (s == null) throw _notSignedIn;
      final data = await _json('POST', '/token/refresh', body: {
        'refresh_token': s.refreshToken,
        if (orgId != null) 'org_id': orgId,
      });
      return _afterRotation(s, data);
    });
  }

  // Runs an operation that rotates the refresh token, never two at once. When nothing is running, `_refreshing` is
  // set synchronously (no await before it), so concurrent callers always see it.
  Future<String> _exclusive(Future<String> Function() operation) async {
    for (var running = _refreshing; running != null; running = _refreshing) {
      try {
        await running;
      } catch (_) {
        // its caller handles it
      }
    }
    final run = operation();
    _refreshing = run;
    try {
      return await run;
    } finally {
      if (identical(_refreshing, run)) _refreshing = null;
    }
  }

  Future<void> _waitForRefresh() async {
    for (;;) {
      final running = _refreshing;
      if (running == null) return;
      try {
        await running;
      } catch (_) {
        // its caller handles it
      }
    }
  }

  Future<String> _afterRotation(_Session used, Map<String, dynamic> data) async {
    final access = data['access_token'];
    if (access is! String) throw const AppAuthException(0, 'unexpected_response', 'No access token in the answer');
    if (_session?.refreshToken != used.refreshToken) {
      throw const AppAuthException(401, 'not_signed_in', 'The session changed while it was being renewed');
    }
    await _storeTokens(data);
    return access;
  }

  /// An `http.Client` adding `Authorization: Bearer <access token>` (renewed when needed) to every request.
  /// With [hosts], only requests to those hosts get the token. [inner] defaults to the SDK's HTTP client.
  http.Client authorizedClient({http.Client? inner, Set<String>? hosts}) =>
      AuthorizedClient(getAccessToken, inner ?? _http, hosts: hosts);

  // --- configuration ---------------------------------------------------------------------------------------------

  /// The pool's public settings: methods, providers, password policy, mode, branding.
  Future<PoolConfig> config() async => PoolConfig.fromJson(await _json('GET', '/config'));

  // --- sign-up and sign-in ---------------------------------------------------------------------------------------

  /// Creates an account with email and password.
  Future<SignInOutcome> signUp({
    required String email,
    required String password,
    String? displayName,
    String? locale,
    String? orgId,
  }) async =>
      _outcome(await _json('POST', '/signup', body: {
        'email': email,
        'password': password,
        'display_name': displayName ?? '',
        if (locale != null) 'locale': locale,
        if (orgId != null) 'org_id': orgId,
      }));

  /// Signs in with email and password.
  Future<SignInOutcome> signInWithPassword({required String email, required String password, String? orgId}) async =>
      _outcome(await _json('POST', '/signin/password', body: {
        'email': email,
        'password': password,
        if (orgId != null) 'org_id': orgId,
      }));

  /// Emails a sign-in code (the answer never tells whether the address has an account).
  Future<void> sendEmailCode(String email) async {
    await _call('POST', '/signin/email-code', body: {'email': email});
  }

  /// Signs in with the emailed code ([email] + [code]) or the link's [token].
  Future<SignInOutcome> signInWithEmailCode({String? email, String? code, String? token, String? orgId}) async =>
      _outcome(await _json('POST', '/signin/email-code/verify', body: {
        if (email != null) 'email': email,
        if (code != null) 'code': code,
        if (token != null) 'token': token,
        if (orgId != null) 'org_id': orgId,
      }));

  /// Signs in as a guest (if the pool allows it); [upgradeAnonymous] turns the guest into a real account.
  Future<SignInOutcome> signInAnonymously() async =>
      _outcome(await _json('POST', '/signin/anonymous', body: const <String, dynamic>{}));

  /// Completes a sign-in that answered [MfaRequired], with a TOTP or recovery [code].
  Future<SignInOutcome> verifyMfa({required String mfaToken, required String code}) async =>
      _outcome(await _json('POST', '/signin/mfa', body: {'mfa_token': mfaToken, 'code': code}));

  /// Starts a TOTP enrollment: during a sign-in ([MfaEnrollRequired]) pass its [mfaToken]; signed in, omit it.
  Future<MfaEnrollment> enrollMfa({String? mfaToken}) async => MfaEnrollment.fromJson(mfaToken != null
      ? await _json('POST', '/mfa/enroll', body: {'mfa_token': mfaToken})
      : await _json('POST', '/mfa/enroll', body: const <String, dynamic>{}, auth: true));

  /// Confirms the enrollment with a first [code]. With [mfaToken] the sign-in completes ([MfaConfirmation.outcome]).
  Future<MfaConfirmation> confirmMfa(String code, {String? mfaToken}) async {
    if (mfaToken != null) {
      final data = await _json('POST', '/mfa/enroll/confirm', body: {'mfa_token': mfaToken, 'code': code});
      final outcome = await _outcome(data);
      return MfaConfirmation(_asStrings(data['recovery_codes']), outcome);
    }
    final data = await _json('POST', '/mfa/enroll/confirm', body: {'code': code}, auth: true);
    await _patchUser((u) => u['mfa'] = {..._asMap(u['mfa']), 'totp': true});
    return MfaConfirmation(_asStrings(data['recovery_codes']), null);
  }

  /// Turns two-step verification off (signed in; a current [code] is required).
  Future<void> disableMfa(String code) async {
    await _call('POST', '/mfa/disable', body: {'code': code}, auth: true);
    await _patchUser((u) => u['mfa'] = {..._asMap(u['mfa']), 'totp': false});
  }

  // --- passwords and emails --------------------------------------------------------------------------------------

  /// Emails a password reset code and link (always answers the same way).
  Future<void> sendPasswordReset(String email) async {
    await _call('POST', '/password/forgot', body: {'email': email});
  }

  /// Sets a new password with the reset link's [token], or with [email] + [code].
  Future<void> resetPassword({String? token, String? email, String? code, required String newPassword}) async {
    await _call('POST', '/password/reset', body: {
      if (token != null) 'token': token,
      if (email != null) 'email': email,
      if (code != null) 'code': code,
      'new_password': newPassword,
    });
  }

  /// Sets the new password a [PasswordChangeRequired] outcome asked for; then sign in again.
  Future<void> changeForcedPassword({required String changeToken, required String newPassword}) async {
    await _call('POST', '/password/reset', body: {'change_token': changeToken, 'new_password': newPassword});
  }

  /// Verifies the email address with the link's [token] or [email] + [code]; returns the user.
  Future<PoolUser?> verifyEmail({String? token, String? email, String? code}) async {
    final data = await _json('POST', '/email/verify', body: {
      if (token != null) 'token': token,
      if (email != null) 'email': email,
      if (code != null) 'code': code,
    });
    if (data['user'] is! Map) return null;
    final user = _asMap(data['user']);
    await _setUser(user);
    return PoolUser.fromJson(user);
  }

  /// Sends the verification email again (signed in).
  Future<void> resendVerification() async {
    await _call('POST', '/email/verify/send', body: const <String, dynamic>{}, auth: true);
  }

  // --- the signed-in user ----------------------------------------------------------------------------------------

  /// The signed-in user, fresh from the pool (also updates [currentUser]).
  Future<PoolUser> me() async {
    final user = await _json('GET', '/me', auth: true);
    await _setUser(user);
    return PoolUser.fromJson(user);
  }

  /// Updates the profile (only the fields given).
  Future<PoolUser> updateProfile({String? displayName, String? photoUrl, String? locale}) async {
    final user = await _json('PATCH', '/me', auth: true, body: {
      if (displayName != null) 'display_name': displayName,
      if (photoUrl != null) 'photo_url': photoUrl,
      if (locale != null) 'locale': locale,
    });
    await _setUser(user);
    return PoolUser.fromJson(user);
  }

  /// Changes the password. Every session of the user ends, this one too: the local session is cleared.
  Future<void> changePassword({String? currentPassword, required String newPassword}) async {
    await _call('POST', '/me/password', auth: true, body: {
      if (currentPassword != null) 'current_password': currentPassword,
      'new_password': newPassword,
    });
    await _save(null);
  }

  /// Starts an email change: a code is sent to [newEmail] ([confirmEmailChange]).
  Future<void> changeEmail(String newEmail) async {
    await _call('POST', '/me/email', body: {'new_email': newEmail}, auth: true);
  }

  /// Confirms the email change with the [code] or the link's [token]; returns the user.
  Future<PoolUser> confirmEmailChange({String? code, String? token}) async {
    final data = await _json('POST', '/me/email/confirm', auth: true, body: {
      if (code != null) 'code': code,
      if (token != null) 'token': token,
    });
    final user = _asMap(data['user']);
    await _setUser(user);
    return PoolUser.fromJson(user);
  }

  /// Turns the signed-in guest into a real account (same id), then renews the tokens (best effort).
  Future<PoolUser> upgradeAnonymous({required String email, required String password}) async {
    final data = await _json('POST', '/me/upgrade', auth: true, body: {'email': email, 'password': password});
    final user = _asMap(data['user']);
    await _setUser(user);
    try {
      await refresh(); // the access token still says "anon" until renewed
    } on AppAuthException {
      // the current token stays valid until it expires
    }
    return PoolUser.fromJson(user);
  }

  /// Deletes the account ([password] required when it has one) and clears the local session.
  Future<void> deleteAccount({String? password}) async {
    await _call('DELETE', '/me', auth: true, body: {if (password != null) 'password': password});
    await _save(null);
  }

  /// Signs out: tells the pool (best effort: revokes the refresh token, ends the session or, with [everywhere], all
  /// the user's sessions) and always clears the local session.
  Future<void> signOut({bool everywhere = false}) async {
    await _ensureLoaded();
    await _waitForRefresh();
    var s = _session;
    if (s != null) {
      try {
        String? bearer = _fresh(s) ? s.accessToken : null;
        if (bearer == null && everywhere) {
          bearer = await getAccessToken(); // "everywhere" needs a valid access token
          s = _session ?? s;
        }
        await _call('POST', '/signout', bearer: bearer, body: {'refresh_token': s.refreshToken, 'everywhere': everywhere});
      } catch (_) {
        // signed out locally anyway
      }
    }
    await _save(null);
  }

  // --- organizations (B2B pools) ---------------------------------------------------------------------------------

  /// The user's organizations and the active one (B2C pools: empty).
  Future<OrganizationList> organizations() async => OrganizationList.fromJson(await _json('GET', '/orgs', auth: true));

  /// Creates an organization (if the pool allows it); the user becomes its owner.
  Future<Organization> createOrganization(String name) async =>
      Organization.fromJson(await _json('POST', '/orgs', body: {'name': name}, auth: true));

  /// Switches the session to the organization [orgId] (new tokens); returns the new active organization.
  Future<ActiveOrg?> switchOrganization(String orgId) async {
    final bearer = await getAccessToken();
    await _exclusive(() async {
      final s = _session;
      if (s == null) throw _notSignedIn;
      final data = await _json('POST', '/orgs/switch', bearer: bearer, body: {'org_id': orgId, 'refresh_token': s.refreshToken});
      return _afterRotation(s, data);
    });
    return currentOrg;
  }

  String _orgPath(String orgId) => '/orgs/${Uri.encodeComponent(orgId)}/members';

  /// A page of the organization's members (owners and admins only).
  Future<MemberPage> members(String orgId, {String q = '', int skip = 0, int limit = 50}) async {
    final query = Uri(queryParameters: {'q': q, 'skip': '$skip', 'limit': '$limit'}).query;
    return MemberPage.fromJson(await _json('GET', '${_orgPath(orgId)}?$query', auth: true));
  }

  /// Adds a member: an existing user joins; an unknown address gets an account with a temporary password.
  Future<AddedMember> addMember(
    String orgId, {
    required String email,
    String? displayName,
    String? password,
    List<String> roles = const [],
  }) async =>
      AddedMember.fromJson(await _json('POST', _orgPath(orgId), auth: true, body: {
        'email': email,
        'display_name': displayName ?? '',
        if (password != null) 'password': password,
        'roles': roles,
      }));

  /// Sets a member's roles; returns them.
  Future<List<String>> setMemberRoles(String orgId, String userId, List<String> roles) async {
    final data = await _json('PATCH', '${_orgPath(orgId)}/${Uri.encodeComponent(userId)}', auth: true, body: {'roles': roles});
    return _asStrings(data['roles']);
  }

  /// Removes a member from the organization.
  Future<void> removeMember(String orgId, String userId) async {
    await _call('DELETE', '${_orgPath(orgId)}/${Uri.encodeComponent(userId)}', auth: true);
  }

  // --- hosted sign-in (OpenID Connect) ---------------------------------------------------------------------------

  /// Builds the `<issuer>/authorize` address (code + PKCE S256, state, nonce) and stores the transaction for
  /// [handleRedirectCallback]. Low level: [signInWithHostedPage] does everything.
  ///
  /// OpenBack extras: [provider] (straight to Google, ...), [orgId] (B2B), [screenHint] `signup`, [prompt]
  /// `none`/`login`, [maxAge], [loginHint], [uiLocales] `it`/`en`.
  Future<AuthorizationRequest> buildAuthorizationRequest({
    String? redirectUri,
    String? provider,
    String? orgId,
    String? prompt,
    String? screenHint,
    String? loginHint,
    int? maxAge,
    String scope = 'openid profile email',
    String? uiLocales,
  }) async {
    await _ensureLoaded();
    final redirect = redirectUri ?? this.redirectUri;
    if (redirect == null || redirect.isEmpty) {
      throw ArgumentError('redirectUri is required for the hosted sign-in');
    }
    final verifier = newCodeVerifier();
    final state = randomUrlSafeString(24);
    final nonce = randomUrlSafeString(24);
    final url = Uri.parse('$issuer/authorize').replace(queryParameters: {
      'response_type': 'code',
      'client_id': clientId,
      'redirect_uri': redirect,
      'scope': scope,
      'state': state,
      'nonce': nonce,
      'code_challenge': codeChallengeS256(verifier),
      'code_challenge_method': 'S256',
      if (provider != null) 'provider': provider,
      if (orgId != null) 'org_id': orgId,
      if (prompt != null) 'prompt': prompt,
      if (screenHint != null) 'screen_hint': screenHint,
      if (loginHint != null) 'login_hint': loginHint,
      if (maxAge != null) 'max_age': '$maxAge',
      if (uiLocales != null) 'ui_locales': uiLocales,
    });
    final request = AuthorizationRequest(
      url: url,
      state: state,
      nonce: nonce,
      codeVerifier: verifier,
      redirectUri: redirect,
    );
    await _storage.write(_pendingKey, jsonEncode(request.toJson()));
    return request;
  }

  Future<AuthorizationRequest?> _takePending() async {
    AuthorizationRequest? pending;
    try {
      final raw = await _storage.read(_pendingKey);
      if (raw != null) pending = AuthorizationRequest.fromJson(jsonDecode(raw));
    } catch (_) {
      pending = null;
    }
    await _storage.delete(_pendingKey); // one use
    return pending;
  }

  /// Completes a hosted sign-in from the callback address [url]: checks `error`, `state` (constant time) and `iss`,
  /// exchanges the code (PKCE), checks the ID token's `nonce`, `aud` and `iss` (decoded, not verified: it comes
  /// straight from the token endpoint over TLS), stores the session and returns the user.
  Future<PoolUser?> handleRedirectCallback(String url) async {
    await _ensureLoaded();
    final params = Uri.parse(url).queryParameters;
    final pending = await _takePending();
    final error = params['error'];
    if (error != null) {
      throw AppAuthException(400, error, params['error_description'] ?? error);
    }
    final code = params['code'];
    if (code == null || code.isEmpty) {
      throw const AppAuthException(400, 'invalid_callback', 'The callback carries no authorization code');
    }
    if (pending == null || !constantTimeEquals(pending.state, params['state'] ?? '')) {
      throw const AppAuthException(400, 'invalid_state', 'Sign-in state mismatch');
    }
    final iss = params['iss'];
    if (iss != null && iss != issuer) {
      throw const AppAuthException(400, 'invalid_issuer', 'Unexpected issuer');
    }
    final data = await _tokenEndpoint({
      'grant_type': 'authorization_code',
      'code': code,
      'redirect_uri': pending.redirectUri,
      'client_id': clientId,
      'code_verifier': pending.codeVerifier,
    });
    final idToken = data['id_token'];
    if (idToken is String) {
      final claims = decodeJwtPayload(idToken);
      if (claims == null) throw const AppAuthException(400, 'invalid_id_token', 'Unreadable ID token');
      final nonce = claims['nonce'];
      if (nonce is! String || !constantTimeEquals(nonce, pending.nonce)) {
        throw const AppAuthException(400, 'invalid_nonce', 'Nonce mismatch');
      }
      final aud = claims['aud'];
      final audOk = aud == clientId || (aud is List && aud.contains(clientId));
      if (!audOk || claims['iss'] != issuer) {
        throw const AppAuthException(400, 'invalid_id_token', 'ID token of another app or issuer');
      }
    }
    if (data['access_token'] is! String) {
      throw const AppAuthException(0, 'unexpected_response', 'No access token in the answer');
    }
    await _storeTokens(data, newSignIn: true);
    try {
      return await me();
    } on AppAuthException {
      return currentUser; // known from the token until /me answers
    }
  }

  String _callbackSchemeFor(String redirect) {
    final explicit = callbackUrlScheme;
    if (explicit != null && explicit.isNotEmpty) return explicit;
    final uri = Uri.parse(redirect);
    // flutter_web_auth_2 on Windows/Linux listens on a loopback port: it wants "http://localhost:<port>".
    if (uri.scheme == 'http' && (uri.host == 'localhost' || uri.host == '127.0.0.1')) {
      return 'http://localhost:${uri.port}';
    }
    return uri.scheme;
  }

  /// Signs in through the pool's hosted page in the platform's authentication browser (`flutter_web_auth_2`) and
  /// returns the user. Throws [AppAuthException] `canceled` when the user closes the browser.
  ///
  /// [preferEphemeral] (iOS/macOS, Android) uses a private browser session: no shared cookies, no "sign in with"
  /// prompt, but the user signs in every time.
  Future<PoolUser?> signInWithHostedPage({
    String? provider,
    String? orgId,
    String? prompt,
    String? screenHint,
    String? loginHint,
    int? maxAge,
    String scope = 'openid profile email',
    String? uiLocales,
    bool preferEphemeral = false,
  }) async {
    final request = await buildAuthorizationRequest(
      provider: provider,
      orgId: orgId,
      prompt: prompt,
      screenHint: screenHint,
      loginHint: loginHint,
      maxAge: maxAge,
      scope: scope,
      uiLocales: uiLocales,
    );
    final String result;
    try {
      result = await _webAuth(
        url: request.url.toString(),
        callbackUrlScheme: _callbackSchemeFor(request.redirectUri),
        preferEphemeral: preferEphemeral,
      );
    } on PlatformException catch (e) {
      await _storage.delete(_pendingKey);
      if (e.code == 'CANCELED') throw AppAuthException(0, 'canceled', 'The sign-in was canceled', cause: e);
      throw AppAuthException(0, 'browser_error', e.message ?? e.code, cause: e);
    } catch (_) {
      await _storage.delete(_pendingKey);
      rethrow;
    }
    return handleRedirectCallback(result);
  }

  /// The pool's end-session address (`<issuer>/logout`) with `client_id`, `id_token_hint`,
  /// [postLogoutRedirectUri] (must be registered in the app's post-logout list) and [state].
  Uri buildLogoutUrl({String? postLogoutRedirectUri, String? state}) {
    final idToken = _session?.idToken;
    return Uri.parse('$issuer/logout').replace(queryParameters: {
      'client_id': clientId,
      if (idToken != null) 'id_token_hint': idToken,
      if (postLogoutRedirectUri != null) 'post_logout_redirect_uri': postLogoutRedirectUri,
      if (state != null) 'state': state,
    });
  }

  /// Signs out ([signOut]) and also ends the hosted page's browser session (its cookie), opening the pool's logout
  /// address in the authentication browser. [postLogoutRedirectUri] (default: the redirect address) must be in the
  /// app's post-logout list, else the browser cannot come back: without one, only the local sign-out happens.
  Future<void> signOutWithHostedPage({
    String? postLogoutRedirectUri,
    bool everywhere = false,
    bool preferEphemeral = false,
  }) async {
    await _ensureLoaded();
    final target = postLogoutRedirectUri ?? redirectUri;
    final url = buildLogoutUrl(postLogoutRedirectUri: target); // before signOut: it carries the id_token_hint
    await signOut(everywhere: everywhere);
    if (target == null || target.isEmpty) return;
    try {
      await _webAuth(url: url.toString(), callbackUrlScheme: _callbackSchemeFor(target), preferEphemeral: preferEphemeral);
    } on PlatformException catch (e) {
      if (e.code != 'CANCELED') throw AppAuthException(0, 'browser_error', e.message ?? e.code, cause: e);
    }
  }
}
