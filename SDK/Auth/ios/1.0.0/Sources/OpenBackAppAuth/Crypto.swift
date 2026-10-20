import CryptoKit
import Foundation
import Security

/// PKCE, random values and base64url (all randomness from `SecRandomCopyBytes`).
enum PKCE {
    static func randomBytes(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw AppAuthError(status: 0, code: "random_failed", message: "The system random generator failed")
        }
        return Data(bytes)
    }

    /// `count` random bytes, base64url encoded.
    static func randomString(_ count: Int = 32) throws -> String {
        base64URL(try randomBytes(count))
    }

    /// A code verifier: 48 random bytes, 64 characters (RFC 7636: 43-128).
    static func codeVerifier() throws -> String {
        try randomString(48)
    }

    /// The S256 challenge of a verifier.
    static func codeChallenge(for verifier: String) -> String {
        base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func base64URLDecode(_ text: String) -> Data? {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 { base64 += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: base64)
    }

    /// Compares two strings in time independent of where they differ.
    static func constantTimeEquals(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8)
        let y = Array(b.utf8)
        var diff = UInt8(truncatingIfNeeded: x.count ^ y.count)
        if x.count != y.count { diff |= 1 }
        for i in 0..<min(x.count, y.count) {
            diff |= x[i] ^ y[i]
        }
        return diff == 0
    }
}

/// `application/x-www-form-urlencoded` and query encoding (only unreserved ASCII characters stay as they are, so `+`
/// and `&` in values are always escaped).
enum FormEncoding {
    private static let unreserved = CharacterSet(charactersIn:
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    static func escape(_ text: String) -> String {
        text.addingPercentEncoding(withAllowedCharacters: unreserved) ?? ""
    }

    static func encode(_ pairs: [(String, String)]) -> String {
        pairs.map { "\(escape($0.0))=\(escape($0.1))" }.joined(separator: "&")
    }
}

/// Decoding of JWT payloads (no verification).
public enum JWT {
    /// Decodes the payload of a JWT WITHOUT verifying it. For display and routing only: your API must verify the token.
    public static func decodePayload(_ token: String) -> [String: JSONValue]? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let data = PKCE.base64URLDecode(String(parts[1])) else { return nil }
        return (try? JSONDecoder().decode(JSONValue.self, from: data))?.objectValue
    }
}
