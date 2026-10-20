/// An error of the user pool (or of the SDK itself).
///
/// [status] is the HTTP status (0 for network failures and errors raised by the SDK without an HTTP answer, such as
/// a canceled browser flow), [code] the machine-readable code (`invalid_credentials`, `weak_password`,
/// `token_expired`, ... or `http_<status>` when the answer has none), [message] a human-readable text and [detail]
/// the raw `detail` of the answer (for `weak_password`: a map with `problems`).
class AppAuthException implements Exception {
  /// Creates an error.
  const AppAuthException(this.status, this.code, this.message, {this.detail, this.cause});

  /// The HTTP status (0 when there was no HTTP answer).
  final int status;

  /// The error code (`invalid_credentials`, `too_many_requests`, `token_expired`, `network_error`, `canceled`, ...).
  final String code;

  /// A human-readable message (the pool's messages are "italiano / English").
  final String message;

  /// The `detail` of the pool's answer: a map (`{code, message, problems?}`), a string or a list (validation errors).
  final Object? detail;

  /// The underlying error, for network failures.
  final Object? cause;

  /// True when the error means the local session is dead (it has been cleared by the SDK).
  bool get isSessionEnded => status == 401 && (code == 'invalid_refresh_token' || code.startsWith('token_'));

  /// The password policy problems of a `weak_password` error (empty otherwise).
  List<String> get problems {
    final d = detail;
    if (d is Map && d['problems'] is List) {
      return (d['problems'] as List).map((e) => e.toString()).toList(growable: false);
    }
    return const [];
  }

  /// Builds the error of a JSON API answer (`{"detail": {"code", "message"}}`, `{"detail": "..."}` or a list).
  factory AppAuthException.fromApi(int status, Object? body, [String? reasonPhrase]) {
    final detail = body is Map ? body['detail'] : null;
    String code = 'http_$status';
    String? message;
    if (detail is Map) {
      if (detail['code'] is String && (detail['code'] as String).isNotEmpty) code = detail['code'] as String;
      if (detail['message'] is String) message = detail['message'] as String;
    } else if (detail is String) {
      message = detail;
    } else if (detail is List && detail.isNotEmpty) {
      final first = detail.first;
      message = first is Map && first['msg'] is String ? first['msg'] as String : first.toString();
    }
    return AppAuthException(status, code, message ?? reasonPhrase ?? 'HTTP $status', detail: detail);
  }

  /// Builds the error of an OAuth answer (`{"error", "error_description"}`).
  factory AppAuthException.fromOAuth(int status, Object? body) {
    final map = body is Map ? body : const {};
    final error = map['error'] is String ? map['error'] as String : 'http_$status';
    final description = map['error_description'] is String ? map['error_description'] as String : error;
    return AppAuthException(status, error, description, detail: body);
  }

  @override
  String toString() => 'AppAuthException($status, $code): $message';
}
