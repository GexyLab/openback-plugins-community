import Foundation
import Security

/// Where the SDK keeps the session (tokens and the signed-in user) and a hosted sign-in in progress.
///
/// Values are JSON strings under the keys `openback.auth.<clientId>` (the session) and `openback.auth.<clientId>.pkce`
/// (the pending hosted sign-in). Implement it to keep them elsewhere. Calls come from the client's actor, one at a
/// time per client.
public protocol TokenStorage: Sendable {
    /// The value under `key`, or nil.
    func get(_ key: String) throws -> String?
    /// Stores `value` under `key`, replacing the previous one in a single write.
    func set(_ value: String, for key: String) throws
    /// Removes `key` (no error when it is missing).
    func remove(_ key: String) throws
}

/// Keeps the values in memory: nothing survives a restart. For tests and apps that must not persist.
public final class InMemoryTokenStorage: TokenStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String]

    public init(_ initial: [String: String] = [:]) {
        values = initial
    }

    /// A copy of the stored values.
    public var snapshot: [String: String] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }

    public func get(_ key: String) throws -> String? {
        lock.lock()
        defer { lock.unlock() }
        return values[key]
    }

    public func set(_ value: String, for key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values[key] = value
    }

    public func remove(_ key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values[key] = nil
    }
}

/// The default storage: the Keychain, one generic password per key (`kSecClassGenericPassword`, service = the key),
/// readable after the first unlock, never migrated to another device (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
/// so background refreshes work while the device is locked and backups do not carry the tokens).
public struct KeychainTokenStorage: TokenStorage {
    /// A Keychain access group shared with your app extensions (nil: the app's default group).
    public let accessGroup: String?
    /// The `kSecAttrAccount` of the items.
    public let account: String
    /// macOS: use the data protection keychain (iOS-style; needs a signed app with a keychain access group
    /// entitlement). Ignored on the other platforms, where it is the only keychain.
    public let useDataProtectionKeychain: Bool

    public init(accessGroup: String? = nil, account: String = "openback-app-auth", useDataProtectionKeychain: Bool = true) {
        self.accessGroup = accessGroup
        self.account = account
        self.useDataProtectionKeychain = useDataProtectionKeychain
    }

    private func query(_ key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        #if os(macOS)
        if useDataProtectionKeychain { query[kSecUseDataProtectionKeychain as String] = true }
        #endif
        return query
    }

    private func failure(_ status: OSStatus, _ action: String) -> AppAuthError {
        AppAuthError(status: 0, code: "storage_error", message: "Keychain \(action) failed (OSStatus \(status))")
    }

    public func get(_ key: String) throws -> String? {
        var search = query(key)
        search[kSecReturnData as String] = true
        search[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(search as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else { throw failure(status, "read") }
        return String(data: data, encoding: .utf8)
    }

    public func set(_ value: String, for key: String) throws {
        let attributes: [String: Any] = [
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(query(key) as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            let add = query(key).merging(attributes) { _, new in new }
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw failure(status, "write") }
    }

    public func remove(_ key: String) throws {
        let status = SecItemDelete(query(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw failure(status, "delete") }
    }
}
