import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Where the SDK keeps the session (tokens and the signed-in user) and the pending hosted sign-in.
///
/// Values are JSON strings under the keys `openback.auth.<clientId>` (the session) and
/// `openback.auth.<clientId>.pkce` (a hosted sign-in in progress). Implement it to keep them elsewhere.
abstract class TokenStorage {
  /// The value under [key], or null.
  Future<String?> read(String key);

  /// Stores [value] under [key], replacing the previous one in a single write.
  Future<void> write(String key, String value);

  /// Removes [key].
  Future<void> delete(String key);
}

/// Keeps the values in memory: nothing survives a restart. Useful for tests and for apps that must not persist.
class MemoryTokenStorage implements TokenStorage {
  /// Creates an empty storage (or one holding [initial]).
  MemoryTokenStorage([Map<String, String>? initial]) : _data = {...?initial};

  final Map<String, String> _data;

  /// A copy of the stored values (for tests).
  Map<String, String> get values => Map.unmodifiable(_data);

  @override
  Future<String?> read(String key) async => _data[key];

  @override
  Future<void> write(String key, String value) async {
    _data[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    _data.remove(key);
  }
}

/// The default storage: `flutter_secure_storage` (iOS/macOS Keychain with "after first unlock, this device only",
/// Android EncryptedSharedPreferences backed by the Keystore, Windows Credential Manager, Linux libsecret, web:
/// WebCrypto-encrypted localStorage).
class SecureTokenStorage implements TokenStorage {
  /// Uses [storage] when given, else a `FlutterSecureStorage` with the options above.
  SecureTokenStorage([FlutterSecureStorage? storage]) : _storage = storage ?? _defaultStorage;

  static const FlutterSecureStorage _defaultStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
    mOptions: MacOsOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
  );

  final FlutterSecureStorage _storage;

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) => _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}
