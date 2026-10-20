import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

// The platform CSPRNG (dart:math Random.secure: /dev/urandom, BCryptGenRandom, SecRandomCopyBytes or
// crypto.getRandomValues on the web).
final Random _secure = Random.secure();

/// Base64url without padding.
String base64UrlNoPadding(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

/// [length] random bytes from the platform CSPRNG, base64url encoded.
String randomUrlSafeString([int length = 32]) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = _secure.nextInt(256);
  }
  return base64UrlNoPadding(bytes);
}

/// A PKCE code verifier: 48 random bytes, 64 characters (RFC 7636 allows 43-128).
String newCodeVerifier() => randomUrlSafeString(48);

/// The S256 code challenge of a verifier.
String codeChallengeS256(String verifier) => base64UrlNoPadding(sha256.convert(ascii.encode(verifier)).bytes);

/// Compares two strings in time independent of where they differ.
bool constantTimeEquals(String a, String b) {
  final x = utf8.encode(a);
  final y = utf8.encode(b);
  var diff = x.length ^ y.length;
  final n = x.length < y.length ? x.length : y.length;
  for (var i = 0; i < n; i++) {
    diff |= x[i] ^ y[i];
  }
  return diff == 0;
}
