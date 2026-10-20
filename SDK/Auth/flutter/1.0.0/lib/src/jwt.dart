import 'dart:convert';

/// Decodes the payload of a JWT WITHOUT verifying it.
///
/// Apps read their own access token's claims (roles, permissions, org_id) for display and routing decisions only:
/// your API must verify the token itself (signature, issuer, audience, expiry) with a server SDK or the gateway's
/// "Authenticated app user" check. Returns null when [token] is not a JWT.
Map<String, dynamic>? decodeJwtPayload(String? token) {
  if (token == null) return null;
  final parts = token.split('.');
  if (parts.length != 3) return null;
  try {
    final json = utf8.decode(base64Url.decode(base64Url.normalize(parts[1])));
    final value = jsonDecode(json);
    return value is Map<String, dynamic> ? value : null;
  } catch (_) {
    return null;
  }
}
