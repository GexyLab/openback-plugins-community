import 'package:http/http.dart' as http;

/// An `http.Client` that adds `Authorization: Bearer <access token>` to every request, renewing the token when it is
/// about to expire. Get one with `OpenBackAppAuth.authorizedClient()`.
///
/// Pass [hosts] to send the token only to your API's hosts (recommended): requests to any other host go out without
/// it, so the token never leaks to a third party by mistake.
class AuthorizedClient extends http.BaseClient {
  /// Wraps [inner]; [token] returns a valid access token (`OpenBackAppAuth.getAccessToken`).
  AuthorizedClient(this._token, this._inner, {Set<String>? hosts, bool closeInner = false})
      : _hosts = hosts == null ? null : {for (final h in hosts) h.toLowerCase()},
        _closeInner = closeInner;

  final Future<String> Function() _token;
  final http.Client _inner;
  final Set<String>? _hosts;
  final bool _closeInner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final hosts = _hosts;
    if (hosts == null || hosts.contains(request.url.host.toLowerCase())) {
      request.headers['Authorization'] = 'Bearer ${await _token()}';
    }
    return _inner.send(request);
  }

  @override
  void close() {
    if (_closeInner) _inner.close();
  }
}
