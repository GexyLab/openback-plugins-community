import Foundation

/// Opens an address in an authentication browser and returns the callback address the pool redirected to.
///
/// The default on iOS and macOS is `SystemWebAuthenticator` (`ASWebAuthenticationSession`). tvOS and watchOS have no
/// authentication browser: use your own screens (JSON API) there, or pass your own implementation.
public protocol WebAuthenticator: Sendable {
    /// Opens `url` and completes with the callback address (one that starts with `callbackURL`).
    /// Throws `AppAuthError.canceled` when the user closes the browser.
    func authenticate(url: URL, callbackURL: URL, prefersEphemeralSession: Bool) async throws -> URL
}

#if canImport(AuthenticationServices) && (os(iOS) || os(macOS))
import AuthenticationServices
#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

/// `ASWebAuthenticationSession`: the system's authentication browser, sharing Safari's cookies unless the session is
/// ephemeral. The callback is a custom scheme (`com.example.app:/oauth2redirect`) or, on iOS 17.4 / macOS 14.4 and
/// later, an https address of an associated domain (universal link).
public struct SystemWebAuthenticator: WebAuthenticator {
    private let anchor: (@MainActor @Sendable () -> ASPresentationAnchor)?

    /// `presentationAnchor` returns the window to present over (default: the key window).
    public init(presentationAnchor: (@MainActor @Sendable () -> ASPresentationAnchor)? = nil) {
        anchor = presentationAnchor
    }

    public func authenticate(url: URL, callbackURL: URL, prefersEphemeralSession: Bool) async throws -> URL {
        try await Self.run(url: url, callbackURL: callbackURL, ephemeral: prefersEphemeralSession, anchor: anchor)
    }

    @MainActor
    private static func run(url: URL, callbackURL: URL, ephemeral: Bool,
                            anchor: (@MainActor @Sendable () -> ASPresentationAnchor)?) async throws -> URL {
        let window = anchor?() ?? keyWindow() ?? ASPresentationAnchor()
        let runner = WebAuthenticationRunner(anchor: window)
        return try await runner.start(url: url, callbackURL: callbackURL, ephemeral: ephemeral)
    }

    @MainActor
    private static func keyWindow() -> ASPresentationAnchor? {
        #if os(iOS)
        return UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first { $0.isKeyWindow }
        #else
        return NSApplication.shared.keyWindow ?? NSApplication.shared.windows.first
        #endif
    }
}

private final class WebAuthenticationRunner: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let anchor: ASPresentationAnchor
    private var session: ASWebAuthenticationSession?

    init(anchor: ASPresentationAnchor) {
        self.anchor = anchor
    }

    @MainActor
    func start(url: URL, callbackURL: URL, ephemeral: Bool) async throws -> URL {
        let scheme = callbackURL.scheme?.lowercased() ?? ""
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
            let completion: (URL?, Error?) -> Void = { url, error in
                if let url {
                    continuation.resume(returning: url)
                } else if let error = error as? ASWebAuthenticationSessionError, error.code == .canceledLogin {
                    continuation.resume(throwing: AppAuthError.canceled)
                } else {
                    continuation.resume(throwing: AppAuthError(status: 0, code: "browser_error",
                                                               message: error?.localizedDescription ?? "The browser failed"))
                }
            }
            let session: ASWebAuthenticationSession
            #if compiler(>=5.10)
            if #available(iOS 17.4, macOS 14.4, *) {
                let callback: ASWebAuthenticationSession.Callback = scheme == "https"
                    ? .https(host: callbackURL.host ?? "", path: callbackURL.path.isEmpty ? "/" : callbackURL.path)
                    : .customScheme(scheme)
                session = ASWebAuthenticationSession(url: url, callback: callback, completionHandler: completion)
            } else {
                session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: completion)
            }
            #else
            session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: completion)
            #endif
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = ephemeral
            self.session = session // keep it alive until the callback
            if !session.start() {
                self.session = nil
                continuation.resume(throwing: AppAuthError(status: 0, code: "browser_error",
                                                           message: "The authentication session could not start"))
            }
        }
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchor
    }
}
#endif

extension AppAuthClient {
    /// The authentication browser of the platform: `SystemWebAuthenticator` on iOS and macOS, none elsewhere.
    static func defaultWebAuthenticator() -> (any WebAuthenticator)? {
        #if canImport(AuthenticationServices) && (os(iOS) || os(macOS))
        return SystemWebAuthenticator()
        #else
        return nil
        #endif
    }
}
