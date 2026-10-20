import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:openback_app_auth_flutter/openback_app_auth_flutter.dart';
import 'package:openback_app_auth_flutter/src/pkce.dart' show codeChallengeS256;

const issuer = 'https://api.example.com/gateway/shop/auth/main';
const clientId = 'uapp_test';
const storageKey = 'openback.auth.$clientId';

String b64(Object json) => base64Url.encode(utf8.encode(jsonEncode(json))).replaceAll('=', '');

/// A JWT-shaped token. The client SDK never verifies signatures (it only decodes), so the signature is a placeholder.
String fakeJwt(Map<String, dynamic> claims, {String typ = 'at+jwt'}) =>
    '${b64({'alg': 'ES256', 'typ': typ, 'kid': 'k1'})}.${b64(claims)}.c2ln';

String accessToken({String sub = 'usr_1', bool anon = false}) => fakeJwt({
      'iss': issuer,
      'sub': sub,
      'aud': clientId,
      'roles': ['member'],
      'permissions': ['*'],
      'email': 'ada@example.com',
      'email_verified': true,
      if (anon) 'anon': true,
    });

Map<String, dynamic> userJson({String id = 'usr_1'}) => {
      'id': id,
      'email': 'ada@example.com',
      'email_verified': true,
      'display_name': 'Ada',
      'photo_url': null,
      'locale': 'en',
      'attributes': {'plan': 'pro'},
      'anonymous': false,
      'created_at': '2026-10-01T10:00:00Z',
      'last_login_at': null,
      'mfa': {'totp': false},
    };

Map<String, dynamic> okOutcome({String refresh = 'obur_1'}) => {
      'status': 'ok',
      'access_token': accessToken(),
      'token_type': 'Bearer',
      'expires_in': 900,
      'refresh_token': refresh,
      'refresh_expires_in': 86400,
      'user': userJson(),
      'org': null,
    };

http.Response jsonResponse(Object body, [int status = 200]) =>
    http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});

http.Response apiError(int status, String code, [Map<String, dynamic> extra = const {}]) =>
    jsonResponse({'detail': {'code': code, 'message': 'msg $code', ...extra}}, status);

class Harness {
  Harness(Future<http.Response> Function(http.Request request) handler, {MemoryTokenStorage? storage, WebAuthenticator? web})
      : storage = storage ?? MemoryTokenStorage() {
    client = MockClient((request) async {
      requests.add(request);
      return handler(request);
    });
    auth = OpenBackAppAuth(
      issuer: '$issuer/',
      clientId: clientId,
      redirectUri: 'com.example.app:/oauth2redirect',
      storage: this.storage,
      httpClient: client,
      webAuthenticator: web,
      clock: () => now,
    );
  }

  final MemoryTokenStorage storage;
  final List<http.Request> requests = [];
  late final MockClient client;
  late final OpenBackAppAuth auth;
  DateTime now = DateTime.utc(2026, 10, 20, 12);

  Map<String, dynamic>? get stored {
    final raw = storage.values[storageKey];
    return raw == null ? null : jsonDecode(raw) as Map<String, dynamic>;
  }

  List<http.Request> to(String pathSuffix) => requests.where((r) => r.url.path.endsWith(pathSuffix)).toList();
}

void main() {
  group('JSON API sign-in', () {
    test('password sign-in stores the session and notifies listeners', () async {
      final h = Harness((r) async => jsonResponse(okOutcome()));
      final states = <AuthState>[];
      final sub = h.auth.authStateChanges.listen(states.add);

      final outcome = await h.auth.signInWithPassword(email: 'ada@example.com', password: 'pw');

      expect(outcome, isA<SignInOk>());
      expect((outcome as SignInOk).user?.displayName, 'Ada');
      expect(outcome.json.containsKey('access_token'), isFalse);
      final req = h.requests.single;
      expect(req.url.toString(), '$issuer/api/v1/signin/password');
      expect(req.headers['X-Client-Id'], clientId);
      expect(req.headers.containsKey('Authorization'), isFalse);
      expect(req.headers['Content-Type'], startsWith('application/json'));
      expect(jsonDecode(req.body), {'email': 'ada@example.com', 'password': 'pw'});

      expect(h.auth.isSignedIn, isTrue);
      expect(h.auth.currentUser?.id, 'usr_1');
      expect(h.auth.currentUser?.attributes['plan'], 'pro');
      expect(h.auth.accessTokenClaims?['roles'], ['member']);
      final stored = h.stored!;
      expect(stored['refreshToken'], 'obur_1');
      expect(stored['expiresAt'], h.now.millisecondsSinceEpoch + 900 * 1000);
      expect(stored.keys, containsAll(['accessToken', 'refreshToken', 'idToken', 'expiresAt', 'user', 'org']));

      await pumpEventQueue();
      expect(states.first.isSignedIn, isFalse); // the state at subscription time
      expect(states.last.user?.id, 'usr_1');
      await sub.cancel();
    });

    test('mfa_required is returned without a session, verifyMfa completes it', () async {
      final h = Harness((r) async {
        if (r.url.path.endsWith('/signin/password')) return jsonResponse({'status': 'mfa_required', 'mfa_token': 'mfa_1'});
        expect(jsonDecode(r.body), {'mfa_token': 'mfa_1', 'code': '123456'});
        return jsonResponse(okOutcome());
      });
      final first = await h.auth.signInWithPassword(email: 'ada@example.com', password: 'pw');
      expect(first, isA<MfaRequired>());
      expect((first as MfaRequired).mfaToken, 'mfa_1');
      expect(h.auth.isSignedIn, isFalse);
      expect(h.stored, isNull);

      final second = await h.auth.verifyMfa(mfaToken: first.mfaToken, code: '123456');
      expect(second, isA<SignInOk>());
      expect(h.auth.isSignedIn, isTrue);
    });

    test('every other outcome is typed', () async {
      final answers = [
        {'status': 'verification_required'},
        {'status': 'mfa_enroll_required', 'mfa_token': 'm'},
        {'status': 'password_change_required', 'change_token': 'c'},
      ];
      var i = 0;
      final h = Harness((r) async => jsonResponse(answers[i++]));
      expect(await h.auth.signUp(email: 'a@b.c', password: 'pw'), isA<VerificationRequired>());
      expect(await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw'), isA<MfaEnrollRequired>());
      final change = await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw');
      expect(change, isA<PasswordChangeRequired>());
      expect((change as PasswordChangeRequired).changeToken, 'c');
      expect(h.auth.isSignedIn, isFalse);
    });

    test('errors are mapped to AppAuthException', () async {
      var answer = apiError(422, 'weak_password', {
        'problems': ['min_length']
      });
      final h = Harness((r) async => answer);
      await expectLater(
        h.auth.signUp(email: 'a@b.c', password: 'x'),
        throwsA(isA<AppAuthException>()
            .having((e) => e.status, 'status', 422)
            .having((e) => e.code, 'code', 'weak_password')
            .having((e) => e.problems, 'problems', ['min_length'])),
      );
      answer = jsonResponse({
        'detail': [
          {'loc': ['body', 'email'], 'msg': 'field required'}
        ]
      }, 422);
      await expectLater(
        h.auth.signInWithPassword(email: '', password: ''),
        throwsA(isA<AppAuthException>().having((e) => e.code, 'code', 'http_422').having((e) => e.message, 'message', 'field required')),
      );
      answer = http.Response('oops', 500);
      await expectLater(h.auth.config(), throwsA(isA<AppAuthException>().having((e) => e.code, 'code', 'http_500')));
    });
  });

  group('tokens', () {
    test('a fresh token is reused, a stale one is refreshed once for concurrent callers', () async {
      final gate = Completer<void>();
      var refreshes = 0;
      final h = Harness((r) async {
        if (r.url.path.endsWith('/signin/password')) return jsonResponse(okOutcome());
        if (r.url.path.endsWith('/token/refresh')) {
          refreshes++;
          expect(jsonDecode(r.body), {'refresh_token': 'obur_1'});
          await gate.future;
          return jsonResponse({
            'access_token': accessToken(),
            'token_type': 'Bearer',
            'expires_in': 900,
            'refresh_token': 'obur_2',
            'refresh_expires_in': 86400,
            'org': null,
          });
        }
        return jsonResponse({}, 404);
      });
      await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw');
      final first = await h.auth.getAccessToken();
      expect(refreshes, 0);

      h.now = h.now.add(const Duration(seconds: 841)); // 59 s left: renew
      final a = h.auth.getAccessToken();
      final b = h.auth.getAccessToken();
      final c = h.auth.refresh();
      await pumpEventQueue();
      gate.complete();
      final tokens = await Future.wait([a, b, c]);
      expect(refreshes, 1);
      expect(tokens.toSet().length, 1);
      expect(tokens.first, isNot(isEmpty));
      expect(first, isNotEmpty);
      expect(h.stored!['refreshToken'], 'obur_2');
      expect(h.auth.currentUser?.id, 'usr_1'); // the user survives a refresh
    });

    test('a refused refresh token clears the session', () async {
      final h = Harness((r) async {
        if (r.url.path.endsWith('/signin/password')) return jsonResponse(okOutcome());
        return apiError(401, 'invalid_refresh_token');
      });
      await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw');
      h.now = h.now.add(const Duration(hours: 1));
      await expectLater(
        h.auth.getAccessToken(),
        throwsA(isA<AppAuthException>().having((e) => e.isSessionEnded, 'isSessionEnded', isTrue)),
      );
      expect(h.auth.isSignedIn, isFalse);
      expect(h.auth.currentUser, isNull);
      expect(h.stored, isNull);
    });

    test('a network error during refresh is surfaced, not retried, and keeps the session', () async {
      var refreshes = 0;
      final h = Harness((r) async {
        if (r.url.path.endsWith('/signin/password')) return jsonResponse(okOutcome());
        refreshes++;
        throw http.ClientException('connection reset');
      });
      await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw');
      h.now = h.now.add(const Duration(hours: 1));
      await expectLater(h.auth.getAccessToken(), throwsA(isA<AppAuthException>().having((e) => e.code, 'code', 'network_error')));
      expect(refreshes, 1);
      expect(h.auth.isSignedIn, isTrue);
      expect(h.stored!['refreshToken'], 'obur_1');
    });

    test('a token_* 401 on a signed-in call clears the session', () async {
      final h = Harness((r) async {
        if (r.url.path.endsWith('/signin/password')) return jsonResponse(okOutcome());
        expect(r.headers['Authorization'], startsWith('Bearer '));
        return apiError(401, 'token_revoked');
      });
      await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw');
      await expectLater(h.auth.me(), throwsA(isA<AppAuthException>()));
      expect(h.auth.isSignedIn, isFalse);
    });

    test('the session is restored from the storage', () async {
      final storage = MemoryTokenStorage({
        storageKey: jsonEncode({
          'accessToken': accessToken(),
          'refreshToken': 'obur_9',
          'idToken': null,
          'expiresAt': DateTime.utc(2026, 10, 20, 13).millisecondsSinceEpoch,
          'user': userJson(),
          'org': {'id': 'org_1', 'name': 'Acme', 'roles': ['owner'], 'choices': 2},
        }),
      });
      final h = Harness((r) async => jsonResponse({}, 500), storage: storage);
      await h.auth.initialize();
      expect(h.auth.currentUser?.email, 'ada@example.com');
      expect(h.auth.currentOrg?.name, 'Acme');
      expect(h.auth.currentOrg?.choices, 2);
      expect(await h.auth.getAccessToken(), accessToken());
      expect(h.requests, isEmpty);
    });

    test('authorizedClient adds the bearer only to the allowed hosts', () async {
      final h = Harness((r) async => r.url.path.endsWith('/signin/password') ? jsonResponse(okOutcome()) : jsonResponse({}));
      await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw');
      final api = h.auth.authorizedClient(hosts: {'api.example.com'});
      await api.get(Uri.parse('https://api.example.com/gateway/shop/orders'));
      await api.get(Uri.parse('https://cdn.other.com/x'));
      expect(h.requests[1].headers['Authorization'], 'Bearer ${accessToken()}');
      expect(h.requests[2].headers.containsKey('Authorization'), isFalse);
    });
  });

  group('account', () {
    test('signOut tells the pool and always clears locally', () async {
      final h = Harness((r) async {
        if (r.url.path.endsWith('/signin/password')) return jsonResponse(okOutcome());
        return http.Response('down', 503);
      });
      await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw');
      await h.auth.signOut(everywhere: true);
      final call = h.to('/signout').single;
      expect(jsonDecode(call.body), {'refresh_token': 'obur_1', 'everywhere': true});
      expect(call.headers['Authorization'], startsWith('Bearer '));
      expect(h.auth.isSignedIn, isFalse);
      expect(h.stored, isNull);
    });

    test('changePassword and deleteAccount end the local session', () async {
      final h = Harness((r) async {
        if (r.url.path.endsWith('/signin/password')) return jsonResponse(okOutcome());
        if (r.url.path.endsWith('/me/password')) return jsonResponse({'status': 'password_changed', 'signed_out': true});
        return jsonResponse({'status': 'deleted'});
      });
      await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw');
      await h.auth.changePassword(currentPassword: 'pw', newPassword: 'new-pw-123');
      expect(h.auth.isSignedIn, isFalse);

      await h.auth.signInWithPassword(email: 'a@b.c', password: 'new-pw-123');
      await h.auth.deleteAccount(password: 'new-pw-123');
      expect(h.to('/me').single.method, 'DELETE');
      expect(h.auth.isSignedIn, isFalse);
    });

    test('updateProfile and switchOrganization update the state', () async {
      final h = Harness((r) async {
        final p = r.url.path;
        if (p.endsWith('/signin/password')) return jsonResponse(okOutcome());
        if (p.endsWith('/me')) return jsonResponse({...userJson(), 'display_name': 'Ada L.'});
        if (p.endsWith('/orgs/switch')) {
          expect(jsonDecode(r.body), {'org_id': 'org_2', 'refresh_token': 'obur_1'});
          return jsonResponse({
            'access_token': accessToken(),
            'expires_in': 900,
            'refresh_token': 'obur_3',
            'org': {'id': 'org_2', 'name': 'Beta', 'roles': ['admin'], 'choices': 2},
          });
        }
        if (p.endsWith('/members')) {
          expect(r.url.queryParameters, {'q': 'bob', 'skip': '0', 'limit': '50'});
          return jsonResponse({
            'items': [
              {'user_id': 'usr_2', 'email': 'bob@example.com', 'display_name': 'Bob', 'disabled': false, 'roles': ['member'], 'created_at': '2026-10-02T00:00:00Z'}
            ],
            'total': 1,
            'roles': [
              {'key': 'member', 'label': 'Member'}
            ],
          });
        }
        return jsonResponse({}, 404);
      });
      await h.auth.signInWithPassword(email: 'a@b.c', password: 'pw');
      final user = await h.auth.updateProfile(displayName: 'Ada L.');
      expect(user.displayName, 'Ada L.');
      expect(jsonDecode(h.to('/me').single.body), {'display_name': 'Ada L.'});
      expect(h.auth.currentUser?.displayName, 'Ada L.');

      final org = await h.auth.switchOrganization('org_2');
      expect(org?.id, 'org_2');
      expect(h.stored!['refreshToken'], 'obur_3');

      final page = await h.auth.members('org_2', q: 'bob');
      expect(page.items.single.email, 'bob@example.com');
      expect(page.roles.single.key, 'member');
    });
  });

  group('hosted sign-in', () {
    late String callback;
    late Uri opened;

    Harness hosted({Map<String, dynamic>? idClaims, bool tokenFails = false}) {
      return Harness((r) async {
        if (r.url.path.endsWith('/token')) {
          if (tokenFails) return jsonResponse({'error': 'invalid_grant', 'error_description': 'PKCE verification failed'}, 400);
          final form = r.bodyFields;
          final pending = opened.queryParameters;
          expect(form['grant_type'], 'authorization_code');
          expect(form['code'], 'code_1');
          expect(form['client_id'], clientId);
          expect(form['redirect_uri'], 'com.example.app:/oauth2redirect');
          expect(codeChallengeS256(form['code_verifier']!), pending['code_challenge']);
          return jsonResponse({
            'access_token': accessToken(),
            'token_type': 'Bearer',
            'expires_in': 900,
            'refresh_token': 'obur_5',
            'id_token': fakeJwt(idClaims ?? {'iss': issuer, 'aud': clientId, 'sub': 'usr_1', 'nonce': pending['nonce']}, typ: 'JWT'),
          });
        }
        if (r.url.path.endsWith('/api/v1/me')) return jsonResponse(userJson());
        return jsonResponse({}, 404);
      }, web: ({required url, required callbackUrlScheme, required preferEphemeral}) async {
        opened = Uri.parse(url);
        expect(callbackUrlScheme, 'com.example.app');
        return callback.replaceAll('STATE', opened.queryParameters['state']!);
      });
    }

    test('PKCE, state and iss are checked, the code is exchanged and the user loaded', () async {
      callback = 'com.example.app:/oauth2redirect?code=code_1&state=STATE&iss=${Uri.encodeComponent(issuer)}';
      final h = hosted();
      final user = await h.auth.signInWithHostedPage(provider: 'uprov_google', uiLocales: 'en');
      expect(user?.displayName, 'Ada');
      final q = opened.queryParameters;
      expect(opened.toString(), startsWith('$issuer/authorize?'));
      expect(q['response_type'], 'code');
      expect(q['code_challenge_method'], 'S256');
      expect(q['scope'], 'openid profile email');
      expect(q['provider'], 'uprov_google');
      expect(q['ui_locales'], 'en');
      expect(h.stored!['refreshToken'], 'obur_5');
      expect(h.stored!['idToken'], isNotNull);
      expect(h.storage.values.containsKey('$storageKey.pkce'), isFalse);

      final logout = h.auth.buildLogoutUrl(postLogoutRedirectUri: 'com.example.app:/signedout', state: 's1');
      expect(logout.path, endsWith('/logout'));
      expect(logout.queryParameters['client_id'], clientId);
      expect(logout.queryParameters['id_token_hint'], h.stored!['idToken']);
      expect(logout.queryParameters['post_logout_redirect_uri'], 'com.example.app:/signedout');
    });

    test('a wrong state is refused', () async {
      callback = 'com.example.app:/oauth2redirect?code=code_1&state=forged';
      final h = hosted();
      await expectLater(h.auth.signInWithHostedPage(), throwsA(isA<AppAuthException>().having((e) => e.code, 'code', 'invalid_state')));
      expect(h.to('/token'), isEmpty);
      expect(h.auth.isSignedIn, isFalse);
    });

    test('a wrong iss is refused', () async {
      callback = 'com.example.app:/oauth2redirect?code=code_1&state=STATE&iss=https%3A%2F%2Fevil.example.com';
      final h = hosted();
      await expectLater(h.auth.signInWithHostedPage(), throwsA(isA<AppAuthException>().having((e) => e.code, 'code', 'invalid_issuer')));
      expect(h.to('/token'), isEmpty);
    });

    test('a wrong nonce is refused', () async {
      callback = 'com.example.app:/oauth2redirect?code=code_1&state=STATE';
      final h = hosted(idClaims: {'iss': issuer, 'aud': clientId, 'sub': 'usr_1', 'nonce': 'other'});
      await expectLater(h.auth.signInWithHostedPage(), throwsA(isA<AppAuthException>().having((e) => e.code, 'code', 'invalid_nonce')));
      expect(h.auth.isSignedIn, isFalse);
    });

    test('an error callback and a token endpoint error are surfaced', () async {
      callback = 'com.example.app:/oauth2redirect?error=access_denied&error_description=denied&state=STATE';
      final h = hosted();
      await expectLater(h.auth.signInWithHostedPage(), throwsA(isA<AppAuthException>().having((e) => e.code, 'code', 'access_denied')));

      callback = 'com.example.app:/oauth2redirect?code=code_1&state=STATE';
      final h2 = hosted(tokenFails: true);
      await expectLater(
        h2.auth.signInWithHostedPage(),
        throwsA(isA<AppAuthException>().having((e) => e.status, 'status', 400).having((e) => e.code, 'code', 'invalid_grant')),
      );
    });
  });
}
