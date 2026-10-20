#if canImport(Combine)
import Combine
import Foundation

/// A SwiftUI-friendly view of an `AppAuthClient`: publishes the signed-in user and organization on the main actor.
///
/// ```swift
/// @StateObject private var auth = AppAuthModel(client: AppAuthClient(issuer: ..., clientId: ...))
/// ...
/// if let user = auth.user { HomeView(user: user) } else { SignInView() }
/// ```
///
/// Call the client (`auth.client.signInWithPassword(...)`) for everything else: the published values follow.
@MainActor
public final class AppAuthModel: ObservableObject {
    /// The signed-in user (nil when signed out).
    @Published public private(set) var user: PoolUser?
    /// The active organization (B2B).
    @Published public private(set) var org: ActiveOrg?
    /// False until the stored session has been read.
    @Published public private(set) var isLoaded = false

    /// Whether a user is signed in.
    public var isSignedIn: Bool { user != nil }

    /// The client.
    public let client: AppAuthClient

    private let listener = ListenerHolder()

    public init(client: AppAuthClient) {
        self.client = client
        let stream = client.authStateChanges()
        listener.task = Task { [weak self] in
            for await state in stream {
                guard let self else { return }
                self.user = state.user
                self.org = state.org
                self.isLoaded = true
            }
        }
    }

    /// Signs in with email and password; see `AppAuthClient.signInWithPassword`.
    public func signInWithPassword(email: String, password: String) async throws -> SignInOutcome {
        try await client.signInWithPassword(email: email, password: password)
    }

    /// Completes a two-step sign-in; see `AppAuthClient.verifyMfa`.
    public func verifyMfa(mfaToken: String, code: String) async throws -> SignInOutcome {
        try await client.verifyMfa(mfaToken: mfaToken, code: code)
    }

    /// Signs in through the hosted page; see `AppAuthClient.signInWithHostedPage`.
    @discardableResult
    public func signInWithHostedPage(_ options: AuthorizationOptions = AuthorizationOptions(),
                                     prefersEphemeralSession: Bool = false) async throws -> PoolUser? {
        try await client.signInWithHostedPage(options, prefersEphemeralSession: prefersEphemeralSession)
    }

    /// Signs out; see `AppAuthClient.signOut`.
    public func signOut(everywhere: Bool = false) async {
        await client.signOut(everywhere: everywhere)
    }
}

// Cancels the listening task when the model goes away (a deinit of a main-actor class cannot touch its isolated state).
private final class ListenerHolder: @unchecked Sendable {
    var task: Task<Void, Never>?

    deinit {
        task?.cancel()
    }
}
#endif
