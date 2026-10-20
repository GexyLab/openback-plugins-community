import Foundation

/// An error of the user pool (or of the SDK itself).
///
/// `status` is the HTTP status (0 when there was no HTTP answer: network failures, a canceled browser, storage
/// errors), `code` the machine-readable code (`invalid_credentials`, `weak_password`, `token_expired`, ... or
/// `http_<status>` when the answer has none), `message` a human-readable text and `detail` the raw `detail` of the
/// answer.
///
/// ```swift
/// do { ... } catch let error as AppAuthError where error.code == "invalid_credentials" { ... }
/// ```
public struct AppAuthError: Error, Equatable, Sendable, CustomStringConvertible, LocalizedError {
    /// The HTTP status (0 without an HTTP answer).
    public let status: Int
    /// The error code.
    public let code: String
    /// A human-readable message (the pool's messages are "italiano / English").
    public let message: String
    /// The `detail` of the pool's answer (`{code, message, problems?}`, a string or a list).
    public let detail: JSONValue?
    /// The URL error of a `network_error`.
    public let urlError: URLError?

    public init(status: Int, code: String, message: String, detail: JSONValue? = nil, urlError: URLError? = nil) {
        self.status = status
        self.code = code
        self.message = message
        self.detail = detail
        self.urlError = urlError
    }

    /// True when the error means the local session is dead (the SDK has cleared it).
    public var isSessionEnded: Bool {
        status == 401 && (code == "invalid_refresh_token" || code.hasPrefix("token_"))
    }

    /// The password policy problems of a `weak_password` error (empty otherwise).
    public var problems: [String] {
        detail?["problems"]?.arrayValue?.compactMap(\.stringValue) ?? []
    }

    public var errorDescription: String? { message }

    public var description: String { "AppAuthError(\(status), \(code)): \(message)" }

    // MARK: - Errors raised by the SDK

    /// No session.
    public static let notSignedIn = AppAuthError(status: 401, code: "not_signed_in", message: "Not signed in")
    /// The user closed the hosted page.
    public static let canceled = AppAuthError(status: 0, code: "canceled", message: "The sign-in was canceled")

    static func unexpected(_ message: String) -> AppAuthError {
        AppAuthError(status: 0, code: "unexpected_response", message: message)
    }

    static func network(_ error: Error) -> AppAuthError {
        AppAuthError(status: 0, code: "network_error", message: "The user pool could not be reached",
                     urlError: error as? URLError)
    }

    static func callback(_ code: String, _ message: String) -> AppAuthError {
        AppAuthError(status: 400, code: code, message: message)
    }

    // MARK: - Errors of the pool's answers

    /// The error of a JSON API answer: `{"detail": {"code", "message"}}`, `{"detail": "..."}` or a validation list.
    static func fromAPI(status: Int, data: Data) -> AppAuthError {
        let body = try? JSONDecoder().decode(JSONValue.self, from: data)
        let detail = body?["detail"]
        var code = "http_\(status)"
        var message: String?
        switch detail {
        case .object(let object)?:
            if let value = object["code"]?.stringValue, !value.isEmpty { code = value }
            message = object["message"]?.stringValue
        case .string(let text)?:
            message = text
        case .array(let items)?:
            message = items.first.flatMap { $0["msg"]?.stringValue }
        default:
            break
        }
        let fallback = HTTPURLResponse.localizedString(forStatusCode: status)
        return AppAuthError(status: status, code: code, message: message ?? fallback, detail: detail)
    }

    /// The error of an OAuth answer: `{"error", "error_description"}`.
    static func fromOAuth(status: Int, data: Data) -> AppAuthError {
        let body = try? JSONDecoder().decode(JSONValue.self, from: data)
        let error = body?["error"]?.stringValue ?? "http_\(status)"
        return AppAuthError(status: status, code: error, message: body?["error_description"]?.stringValue ?? error, detail: body)
    }
}
