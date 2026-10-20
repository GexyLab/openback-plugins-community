// SwiftUI example of openback-app-auth-ios: email + password sign-in with the two-step branch, the pool's hosted
// page, a call to your API with the access token, sign-out.
//
// Not a full Xcode project: create an iOS (or macOS) App project in Xcode, add the package (File > Add Package
// Dependencies... > Add Local... > SDK/Auth/ios/1.0.0), replace the generated App file with this one and set the
// three constants below. Register the app in the pool as `native` with the redirect address
// `com.example.app:/oauth2redirect` (also in its post-logout list for the hosted sign-out).
import OpenBackAppAuth
import SwiftUI

private enum Settings {
    static let issuer = "https://api.example.com/gateway/shop/auth/main"
    static let clientId = "uapp_example"
    static let redirectURI = "com.example.app:/oauth2redirect"
    static let apiURL = URL(string: "https://api.example.com/gateway/shop/orders")!
}

@main
struct OpenBackAuthExampleApp: App {
    @StateObject private var auth = AppAuthModel(client: AppAuthClient(issuer: Settings.issuer,
                                                                      clientId: Settings.clientId,
                                                                      redirectURI: Settings.redirectURI))

    var body: some Scene {
        WindowGroup {
            Group {
                if !auth.isLoaded {
                    ProgressView()
                } else if let user = auth.user {
                    HomeView(user: user)
                } else {
                    SignInView()
                }
            }
            .environmentObject(auth)
        }
    }
}

@MainActor
struct SignInView: View {
    @EnvironmentObject private var auth: AppAuthModel
    @State private var email = ""
    @State private var password = ""
    @State private var code = ""
    @State private var mfaToken: String?
    @State private var message: String?
    @State private var busy = false

    var body: some View {
        Form {
            if let mfaToken {
                Section("Two-step verification") {
                    TextField("Code from your authenticator app", text: $code)
                        .textContentType(.oneTimeCode)
                    Button("Verify") { run { try await handle(auth.verifyMfa(mfaToken: mfaToken, code: code)) } }
                }
            } else {
                Section("Sign in") {
                    TextField("Email", text: $email)
                        .textContentType(.username)
                    SecureField("Password", text: $password)
                        .textContentType(.password)
                    Button("Sign in") { run { try await handle(auth.signInWithPassword(email: email, password: password)) } }
                }
                Section {
                    Button("Sign in with the hosted page") { run { _ = try await auth.signInWithHostedPage() } }
                }
            }
            if let message { Text(message).foregroundStyle(.secondary) }
        }
        .disabled(busy)
    }

    private func handle(_ outcome: SignInOutcome) {
        switch outcome {
        case .ok:
            mfaToken = nil // AppAuthModel.user changes: the home view appears
        case .mfaRequired(let token):
            mfaToken = token
            code = ""
            message = nil
        case .mfaEnrollRequired:
            message = "Two-step verification is required: set it up in the hosted page or your enrollment screen."
        case .passwordChangeRequired:
            message = "Your administrator asks you to choose a new password."
        case .verificationRequired:
            message = "Check your inbox: verify your email address, then sign in again."
        }
    }

    private func run(_ action: @escaping () async throws -> Void) {
        busy = true
        message = nil
        Task {
            defer { busy = false }
            do {
                try await action()
            } catch let error as AppAuthError where error.code == "canceled" {
                // the user closed the hosted page
            } catch let error as AppAuthError {
                message = "\(error.code): \(error.message)" // never print tokens or passwords
            } catch {
                message = error.localizedDescription
            }
        }
    }
}

@MainActor
struct HomeView: View {
    @EnvironmentObject private var auth: AppAuthModel
    let user: PoolUser
    @State private var apiResult: String?

    var body: some View {
        List {
            Section("Signed in") {
                Text(user.displayName.isEmpty ? (user.email ?? user.id) : user.displayName).font(.headline)
                Text(user.anonymous ? "Guest account" : (user.email ?? ""))
                if let org = auth.org { Text("Organization: \(org.name ?? org.id)") }
            }
            Section {
                Button("Call my API") { Task { await callAPI() } }
                if let apiResult { Text(apiResult) }
            }
            Section {
                Button("Sign out") { Task { await auth.signOut() } }
                Button("Sign out (also from the hosted page)") {
                    Task { try? await auth.client.signOutWithHostedPage() }
                }
            }
        }
    }

    private func callAPI() async {
        do {
            let (_, response) = try await URLSession.shared.data(for: URLRequest(url: Settings.apiURL), authorizedBy: auth.client)
            apiResult = "HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)"
        } catch let error as AppAuthError {
            apiResult = "\(error.code): \(error.message)"
        } catch {
            apiResult = "Network error"
        }
    }
}
