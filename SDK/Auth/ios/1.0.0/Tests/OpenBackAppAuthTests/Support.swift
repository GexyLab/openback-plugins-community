import CryptoKit
import Foundation
@testable import OpenBackAppAuth

let testIssuer = "https://api.example.com/gateway/shop/auth/main"
let testClientId = "uapp_test"
let testStorageKey = "openback.auth.uapp_test"
let testRedirect = "com.example.app:/oauth2redirect"

/// Signs test tokens with a P-256 key generated for the test run (ES256, as the pool does). The client SDK never
/// verifies signatures (it only decodes); real signatures keep the tokens realistic.
enum TestTokens {
    static let key = P256.Signing.PrivateKey()

    static func jwt(_ claims: [String: Any], typ: String = "at+jwt") -> String {
        let header = PKCE.base64URL(try! JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": typ, "kid": "test-key"]))
        let payload = PKCE.base64URL(try! JSONSerialization.data(withJSONObject: claims))
        let input = "\(header).\(payload)"
        let signature = try! key.signature(for: Data(input.utf8)).rawRepresentation
        return "\(input).\(PKCE.base64URL(signature))"
    }

    static func access(sub: String = "usr_1", anon: Bool = false) -> String {
        var claims: [String: Any] = [
            "iss": testIssuer, "sub": sub, "aud": testClientId, "azp": testClientId,
            "exp": 4_102_444_800, "iat": 1_760_000_000, "roles": ["member"], "permissions": ["*"],
            "email": "ada@example.com", "email_verified": true,
        ]
        if anon { claims["anon"] = true }
        return jwt(claims)
    }

    static let accessToken = access()
}

func userJSON(id: String = "usr_1", displayName: String = "Ada") -> [String: Any] {
    [
        "id": id, "email": "ada@example.com", "email_verified": true, "display_name": displayName,
        "photo_url": NSNull(), "locale": "en", "attributes": ["plan": "pro"], "anonymous": false,
        "created_at": "2026-10-01T10:00:00Z", "last_login_at": NSNull(), "mfa": ["totp": false],
    ]
}

func okOutcome(refresh: String = "obur_1") -> [String: Any] {
    [
        "status": "ok", "access_token": TestTokens.accessToken, "token_type": "Bearer", "expires_in": 900,
        "refresh_token": refresh, "refresh_expires_in": 86_400, "user": userJSON(), "org": NSNull(),
    ]
}

/// A recorded request with its body (URLProtocol hands bodies over as streams).
struct Recorded {
    let request: URLRequest
    let body: Data

    var path: String { request.url?.path ?? "" }
    var json: [String: Any]? { try? JSONSerialization.jsonObject(with: body) as? [String: Any] }
    var form: [String: String] {
        var out: [String: String] = [:]
        for pair in String(decoding: body, as: UTF8.self).split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            let name = parts[0].removingPercentEncoding ?? parts[0]
            out[name] = parts.count > 1 ? (parts[1].removingPercentEncoding ?? parts[1]) : ""
        }
        return out
    }
    func header(_ name: String) -> String? { request.value(forHTTPHeaderField: name) }
}

enum StubAnswer {
    case json(Int, [String: Any])
    case raw(Int, Data)
    case failure(URLError)
}

/// The HTTP stub: a handler per test, every request recorded. Tests run one at a time.
final class Stub: @unchecked Sendable {
    static let shared = Stub()

    private let lock = NSLock()
    private var handler: (Recorded) -> (StubAnswer, TimeInterval) = { _ in (.json(404, [:]), 0) }
    private var recorded: [Recorded] = []

    func reset(_ handler: @escaping (Recorded) -> (StubAnswer, TimeInterval)) {
        lock.lock()
        defer { lock.unlock() }
        self.handler = handler
        recorded = []
    }

    var requests: [Recorded] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    func requests(endingWith suffix: String) -> [Recorded] {
        requests.filter { $0.path.hasSuffix(suffix) }
    }

    fileprivate func answer(_ record: Recorded) -> (StubAnswer, TimeInterval) {
        lock.lock()
        recorded.append(record)
        let handler = self.handler
        lock.unlock()
        return handler(record)
    }
}

final class StubURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let record = Recorded(request: request, body: Self.body(of: request))
        let (answer, delay) = Stub.shared.answer(record)
        let deliver = { [weak self] in
            guard let self, let client = self.client else { return }
            switch answer {
            case .failure(let error):
                client.urlProtocol(self, didFailWithError: error)
                return
            case .json(let status, let object):
                let data = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
                self.respond(client, status, data)
            case .raw(let status, let data):
                self.respond(client, status, data)
            }
        }
        if delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + delay, execute: deliver)
        } else {
            deliver()
        }
    }

    private func respond(_ client: URLProtocolClient, _ status: Int, _ data: Data) {
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": "application/json"])!
        client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client.urlProtocol(self, didLoad: data)
        client.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func body(of request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}

/// A controllable clock.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date(timeIntervalSince1970: 1_792_000_000)

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func advance(_ seconds: TimeInterval) {
        lock.lock()
        value = value.addingTimeInterval(seconds)
        lock.unlock()
    }
}

/// A fake authentication browser: records the address it was asked to open and answers with a callback.
final class FakeBrowser: WebAuthenticator, @unchecked Sendable {
    private let lock = NSLock()
    private var answer: (URL) -> URL
    private(set) var opened: URL?

    init(answer: @escaping (URL) -> URL) {
        self.answer = answer
    }

    func authenticate(url: URL, callbackURL: URL, prefersEphemeralSession: Bool) async throws -> URL {
        lock.lock()
        opened = url
        let answer = self.answer
        lock.unlock()
        return answer(url)
    }
}

func query(_ url: URL?) -> [String: String] {
    guard let url, let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else { return [:] }
    var out: [String: String] = [:]
    for item in items { out[item.name] = item.value }
    return out
}

func makeClient(storage: InMemoryTokenStorage = InMemoryTokenStorage(), clock: TestClock = TestClock(),
                browser: (any WebAuthenticator)? = nil) -> AppAuthClient {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [StubURLProtocol.self]
    return AppAuthClient(issuer: testIssuer + "/", clientId: testClientId, redirectURI: testRedirect,
                         storage: storage, urlSession: URLSession(configuration: configuration),
                         webAuthenticator: browser, clock: { clock.now })
}

func storedSession(_ storage: InMemoryTokenStorage) -> [String: Any]? {
    guard let raw = storage.snapshot[testStorageKey] else { return nil }
    return try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any]
}
