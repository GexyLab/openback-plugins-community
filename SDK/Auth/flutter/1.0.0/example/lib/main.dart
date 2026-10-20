// Example: sign in with email + password (with the two-step verification branch), or through the pool's hosted page,
// then call your API with the access token.
//
//   flutter run \
//     --dart-define=OPENBACK_ISSUER=https://api.example.com/gateway/shop/auth/main \
//     --dart-define=OPENBACK_CLIENT_ID=uapp_... \
//     --dart-define=OPENBACK_API=https://api.example.com/gateway/shop/orders
//
// Register the app in the pool as `native` (mobile/desktop) or `spa` (web) with the redirect address printed on screen.
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:openback_app_auth_flutter/openback_app_auth_flutter.dart';

const String issuer = String.fromEnvironment('OPENBACK_ISSUER', defaultValue: 'https://api.example.com/gateway/shop/auth/main');
const String clientId = String.fromEnvironment('OPENBACK_CLIENT_ID', defaultValue: 'uapp_example');
const String apiUrl = String.fromEnvironment('OPENBACK_API', defaultValue: 'https://api.example.com/gateway/shop/orders');
const String redirectOverride = String.fromEnvironment('OPENBACK_REDIRECT_URI');

String redirectUri() {
  if (redirectOverride.isNotEmpty) return redirectOverride;
  if (kIsWeb) return '${Uri.base.origin}/auth.html'; // web/auth.html posts the result back to the app
  if (defaultTargetPlatform == TargetPlatform.windows || defaultTargetPlatform == TargetPlatform.linux) {
    return 'http://localhost:43823/callback'; // flutter_web_auth_2 listens on this loopback port
  }
  return 'com.example.app:/oauth2redirect'; // iOS, macOS, Android: the app's custom scheme
}

final OpenBackAppAuth auth = OpenBackAppAuth(issuer: issuer, clientId: clientId, redirectUri: redirectUri());

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ExampleApp());
}

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OpenBack App Auth',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      home: StreamBuilder<AuthState>(
        stream: auth.authStateChanges,
        builder: (context, snapshot) {
          final state = snapshot.data;
          if (state == null) return const Scaffold(body: Center(child: CircularProgressIndicator()));
          return state.isSignedIn ? HomePage(user: state.user!) : const SignInPage();
        },
      ),
    );
  }
}

class SignInPage extends StatefulWidget {
  const SignInPage({super.key});

  @override
  State<SignInPage> createState() => _SignInPageState();
}

class _SignInPageState extends State<SignInPage> {
  final _email = TextEditingController();
  final _password = TextEditingController();
  bool _busy = false;
  String? _message;

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await action();
    } on AppAuthException catch (e) {
      // Show the code and message; never print tokens or passwords.
      if (mounted) setState(() => _message = e.code == 'canceled' ? null : '${e.code}: ${e.message}');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _signInWithPassword() => _run(() async {
        var outcome = await auth.signInWithPassword(email: _email.text.trim(), password: _password.text);
        if (outcome is MfaRequired) {
          final code = await _ask('Two-step verification', 'Code from your authenticator app (or a recovery code)');
          if (code == null) return;
          outcome = await auth.verifyMfa(mfaToken: outcome.mfaToken, code: code);
        }
        switch (outcome) {
          case SignInOk():
            break; // authStateChanges shows the home page
          case VerificationRequired():
            setState(() => _message = 'Check your inbox: verify your email address, then sign in again.');
          case MfaRequired():
            setState(() => _message = 'Wrong code.');
          case MfaEnrollRequired(:final mfaToken):
            final enrollment = await auth.enrollMfa(mfaToken: mfaToken);
            final code = await _ask('Set up two-step verification',
                'Add this key to your authenticator app, then enter its code:\n${enrollment.secret}');
            if (code == null) return;
            final done = await auth.confirmMfa(code, mfaToken: mfaToken);
            setState(() => _message = 'Keep your recovery codes: ${done.recoveryCodes.join(' ')}');
          case PasswordChangeRequired(:final changeToken):
            final newPassword = await _ask('New password', 'Your administrator asks you to choose a new password', obscure: true);
            if (newPassword == null) return;
            await auth.changeForcedPassword(changeToken: changeToken, newPassword: newPassword);
            setState(() => _message = 'Password changed: sign in with the new one.');
        }
      });

  Future<void> _signInWithHostedPage() => _run(() async {
        await auth.signInWithHostedPage();
      });

  Future<String?> _ask(String title, String hint, {bool obscure = false}) {
    final controller = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          obscureText: obscure,
          autofocus: true,
          decoration: InputDecoration(helperText: hint, helperMaxLines: 4),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, controller.text.trim()), child: const Text('OK')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Sign in')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _email,
            decoration: const InputDecoration(labelText: 'Email'),
            keyboardType: TextInputType.emailAddress,
            autofillHints: const [AutofillHints.email],
          ),
          TextField(
            controller: _password,
            decoration: const InputDecoration(labelText: 'Password'),
            obscureText: true,
            autofillHints: const [AutofillHints.password],
          ),
          const SizedBox(height: 16),
          FilledButton(onPressed: _busy ? null : _signInWithPassword, child: const Text('Sign in')),
          const SizedBox(height: 8),
          OutlinedButton(onPressed: _busy ? null : _signInWithHostedPage, child: const Text('Sign in with the hosted page')),
          if (_message != null) Padding(padding: const EdgeInsets.only(top: 16), child: Text(_message!)),
          const SizedBox(height: 24),
          Text('Redirect address to register: ${redirectUri()}', style: Theme.of(context).textTheme.bodySmall),
        ],
      ),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key, required this.user});

  final PoolUser user;

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  String? _apiResult;

  Future<void> _callApi() async {
    // Only requests to the API's host get the token.
    final client = auth.authorizedClient(hosts: {Uri.parse(apiUrl).host});
    try {
      final res = await client.get(Uri.parse(apiUrl));
      setState(() => _apiResult = 'HTTP ${res.statusCode}');
    } on AppAuthException catch (e) {
      setState(() => _apiResult = '${e.code}: ${e.message}');
    } catch (_) {
      setState(() => _apiResult = 'Network error');
    }
  }

  @override
  Widget build(BuildContext context) {
    final user = widget.user;
    final org = auth.currentOrg;
    return Scaffold(
      appBar: AppBar(title: const Text('Signed in')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(user.displayName.isEmpty ? (user.email ?? user.id) : user.displayName,
              style: Theme.of(context).textTheme.headlineSmall),
          Text(user.anonymous ? 'Guest account' : (user.email ?? '')),
          if (org != null) Text('Organization: ${org.name ?? org.id} (${org.roles.join(', ')})'),
          Text('Roles: ${(auth.accessTokenClaims?['roles'] as List?)?.join(', ') ?? '-'}'),
          const SizedBox(height: 16),
          FilledButton(onPressed: _callApi, child: const Text('Call my API')),
          if (_apiResult != null) Text(_apiResult!),
          const SizedBox(height: 16),
          OutlinedButton(onPressed: () => auth.signOut(), child: const Text('Sign out')),
          TextButton(
            onPressed: () => auth.signOutWithHostedPage(),
            child: const Text('Sign out (also from the hosted page)'),
          ),
        ],
      ),
    );
  }
}
