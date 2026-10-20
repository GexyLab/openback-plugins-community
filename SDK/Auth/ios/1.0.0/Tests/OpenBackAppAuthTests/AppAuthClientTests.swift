import XCTest
@testable import OpenBackAppAuth

final class AppAuthClientTests: XCTestCase {
    private func expectError(_ code: String, file: StaticString = #filePath, line: UInt = #line,
                             _ body: () async throws -> Void) async {
        do {
            try await body()
            XCTFail("expected \(code)", file: file, line: line)
        } catch let error as AppAuthError {
            XCTAssertEqual(error.code, code, file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
    }

    // MARK: - JSON API sign-in

    func testPasswordSignInStoresTheSession() async throws {
        Stub.shared.reset { _ in (.json(200, okOutcome()), 0) }
        let storage = InMemoryTokenStorage()
        let auth = makeClient(storage: storage)

        let outcome = try await auth.signInWithPassword(email: "ada@example.com", password: "pw")

        guard case .ok(let user, let org) = outcome else { return XCTFail("not ok: \(outcome)") }
        XCTAssertEqual(user?.displayName, "Ada")
        XCTAssertNil(org)
        let request = try XCTUnwrap(Stub.shared.requests.first)
        XCTAssertEqual(request.request.url?.absoluteString, "\(testIssuer)/api/v1/signin/password")
        XCTAssertEqual(request.header("X-Client-Id"), testClientId)
        XCTAssertNil(request.header("Authorization"))
        XCTAssertEqual(request.json?["email"] as? String, "ada@example.com")
        XCTAssertNil(request.json?["org_id"])

        let signedIn = await auth.isSignedIn
        XCTAssertTrue(signedIn)
        let current = await auth.currentUser
        XCTAssertEqual(current?.attributes["plan"], .string("pro"))
        let claims = await auth.accessTokenClaims
        XCTAssertEqual(claims?["roles"], .array([.string("member")]))
        let stored = try XCTUnwrap(storedSession(storage))
        XCTAssertEqual(stored["refreshToken"] as? String, "obur_1")
        XCTAssertEqual(Set(stored.keys), ["accessToken", "refreshToken", "idToken", "expiresAt", "user", "org"])
    }

    func testMfaRequiredThenVerify() async throws {
        Stub.shared.reset { r in
            if r.path.hasSuffix("/signin/password") { return (.json(200, ["status": "mfa_required", "mfa_token": "mfa_1"]), 0) }
            XCTAssertEqual(r.json?["mfa_token"] as? String, "mfa_1")
            XCTAssertEqual(r.json?["code"] as? String, "123456")
            return (.json(200, okOutcome()), 0)
        }
        let storage = InMemoryTokenStorage()
        let auth = makeClient(storage: storage)
        let first = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        XCTAssertEqual(first, .mfaRequired(mfaToken: "mfa_1"))
        XCTAssertNil(storedSession(storage))
        let signedInBefore = await auth.isSignedIn
        XCTAssertFalse(signedInBefore)

        let second = try await auth.verifyMfa(mfaToken: "mfa_1", code: "123456")
        XCTAssertEqual(second.status, "ok")
        let signedInAfter = await auth.isSignedIn
        XCTAssertTrue(signedInAfter)
    }

    func testOtherOutcomesAreTyped() async throws {
        let answers: [[String: Any]] = [
            ["status": "verification_required"],
            ["status": "mfa_enroll_required", "mfa_token": "m"],
            ["status": "password_change_required", "change_token": "c"],
        ]
        var index = 0
        let lock = NSLock()
        Stub.shared.reset { _ in
            lock.lock(); defer { lock.unlock() }
            let answer = answers[index]
            index += 1
            return (.json(200, answer), 0)
        }
        let auth = makeClient()
        let a = try await auth.signUp(email: "a@b.c", password: "pw")
        let b = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        let c = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        XCTAssertEqual(a, .verificationRequired)
        XCTAssertEqual(b, .mfaEnrollRequired(mfaToken: "m"))
        XCTAssertEqual(c, .passwordChangeRequired(changeToken: "c"))
    }

    func testErrorsAreMapped() async throws {
        Stub.shared.reset { r in
            if r.path.hasSuffix("/signup") {
                return (.json(422, ["detail": ["code": "weak_password", "message": "weak", "problems": ["min_length"]]]), 0)
            }
            if r.path.hasSuffix("/signin/password") {
                return (.json(422, ["detail": [["loc": ["body", "email"], "msg": "field required"]]]), 0)
            }
            return (.raw(500, Data("oops".utf8)), 0)
        }
        let auth = makeClient()
        do {
            _ = try await auth.signUp(email: "a@b.c", password: "x")
            XCTFail("expected an error")
        } catch let error as AppAuthError {
            XCTAssertEqual(error.status, 422)
            XCTAssertEqual(error.code, "weak_password")
            XCTAssertEqual(error.problems, ["min_length"])
        }
        do {
            _ = try await auth.signInWithPassword(email: "", password: "")
            XCTFail("expected an error")
        } catch let error as AppAuthError {
            XCTAssertEqual(error.code, "http_422")
            XCTAssertEqual(error.message, "field required")
        }
        await expectError("http_500") { _ = try await auth.config() }
    }

    // MARK: - Tokens

    func testConcurrentCallersShareOneRefresh() async throws {
        let refreshes = Counter()
        Stub.shared.reset { r in
            if r.path.hasSuffix("/signin/password") { return (.json(200, okOutcome()), 0) }
            if r.path.hasSuffix("/token/refresh") {
                refreshes.increment()
                XCTAssertEqual(r.json?["refresh_token"] as? String, "obur_1")
                return (.json(200, ["access_token": TestTokens.access(sub: "usr_1"), "token_type": "Bearer", "expires_in": 900,
                                    "refresh_token": "obur_2", "refresh_expires_in": 86_400, "org": NSNull()]), 0.3)
            }
            return (.json(404, [:]), 0)
        }
        let storage = InMemoryTokenStorage()
        let clock = TestClock()
        let auth = makeClient(storage: storage, clock: clock)
        _ = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        _ = try await auth.accessToken()
        XCTAssertEqual(refreshes.value, 0)

        clock.advance(841) // 59 s left: renew
        async let a = auth.accessToken()
        async let b = auth.accessToken()
        async let c = auth.refresh()
        let tokens = try await [a, b, c]
        XCTAssertEqual(refreshes.value, 1)
        XCTAssertEqual(Set(tokens).count, 1)
        XCTAssertEqual(storedSession(storage)?["refreshToken"] as? String, "obur_2")
        let user = await auth.currentUser
        XCTAssertEqual(user?.id, "usr_1")
    }

    func testRefusedRefreshTokenClearsTheSession() async throws {
        Stub.shared.reset { r in
            if r.path.hasSuffix("/signin/password") { return (.json(200, okOutcome()), 0) }
            return (.json(401, ["detail": ["code": "invalid_refresh_token", "message": "expired"]]), 0)
        }
        let storage = InMemoryTokenStorage()
        let clock = TestClock()
        let auth = makeClient(storage: storage, clock: clock)
        let states = StateRecorder()
        let subscription = auth.onAuthStateChanged { states.append($0) }
        defer { subscription.cancel() }
        try await Task.sleep(nanoseconds: 50_000_000) // let the listener register
        _ = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        clock.advance(3600)
        do {
            _ = try await auth.accessToken()
            XCTFail("expected an error")
        } catch let error as AppAuthError {
            XCTAssertTrue(error.isSessionEnded)
        }
        let signedIn = await auth.isSignedIn
        XCTAssertFalse(signedIn)
        XCTAssertNil(storedSession(storage))
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(states.values.last?.isSignedIn, false)
        XCTAssertTrue(states.values.contains { $0.isSignedIn })
    }

    func testNetworkErrorDuringRefreshKeepsTheSession() async throws {
        let refreshes = Counter()
        Stub.shared.reset { r in
            if r.path.hasSuffix("/signin/password") { return (.json(200, okOutcome()), 0) }
            refreshes.increment()
            return (.failure(URLError(.networkConnectionLost)), 0)
        }
        let storage = InMemoryTokenStorage()
        let clock = TestClock()
        let auth = makeClient(storage: storage, clock: clock)
        _ = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        clock.advance(3600)
        await expectError("network_error") { _ = try await auth.accessToken() }
        XCTAssertEqual(refreshes.value, 1)
        let signedIn = await auth.isSignedIn
        XCTAssertTrue(signedIn)
        XCTAssertEqual(storedSession(storage)?["refreshToken"] as? String, "obur_1")
    }

    func testTokenErrorOnASignedInCallClearsTheSession() async throws {
        Stub.shared.reset { r in
            if r.path.hasSuffix("/signin/password") { return (.json(200, okOutcome()), 0) }
            XCTAssertEqual(r.header("Authorization"), "Bearer \(TestTokens.accessToken)")
            return (.json(401, ["detail": ["code": "token_revoked", "message": "revoked"]]), 0)
        }
        let auth = makeClient()
        _ = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        await expectError("token_revoked") { _ = try await auth.me() }
        let signedIn = await auth.isSignedIn
        XCTAssertFalse(signedIn)
    }

    func testSessionIsRestoredFromStorage() async throws {
        Stub.shared.reset { _ in (.json(500, [:]), 0) }
        let clock = TestClock()
        let session: [String: Any] = [
            "accessToken": TestTokens.accessToken, "refreshToken": "obur_9", "idToken": NSNull(),
            "expiresAt": (clock.now.timeIntervalSince1970 + 3600) * 1000,
            "user": userJSON(), "org": ["id": "org_1", "name": "Acme", "roles": ["owner"], "choices": 2],
        ]
        let raw = String(decoding: try JSONSerialization.data(withJSONObject: session), as: UTF8.self)
        let auth = makeClient(storage: InMemoryTokenStorage([testStorageKey: raw]), clock: clock)
        let user = await auth.currentUser
        let org = await auth.currentOrg
        XCTAssertEqual(user?.email, "ada@example.com")
        XCTAssertEqual(org?.choices, 2)
        let token = try await auth.accessToken()
        XCTAssertEqual(token, TestTokens.accessToken)
        XCTAssertTrue(Stub.shared.requests.isEmpty)
    }

    func testAuthorizedRequestAddsTheBearer() async throws {
        Stub.shared.reset { r in (.json(200, r.path.hasSuffix("/signin/password") ? okOutcome() : [:]), 0) }
        let auth = makeClient()
        _ = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        let request = try await auth.authorize(URLRequest(url: URL(string: "https://api.example.com/gateway/shop/orders")!))
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer \(TestTokens.accessToken)")
    }

    // MARK: - Account

    func testSignOutTellsThePoolAndAlwaysClears() async throws {
        Stub.shared.reset { r in
            if r.path.hasSuffix("/signin/password") { return (.json(200, okOutcome()), 0) }
            return (.raw(503, Data("down".utf8)), 0)
        }
        let storage = InMemoryTokenStorage()
        let auth = makeClient(storage: storage)
        _ = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        await auth.signOut(everywhere: true)
        let call = try XCTUnwrap(Stub.shared.requests(endingWith: "/signout").first)
        XCTAssertEqual(call.json?["refresh_token"] as? String, "obur_1")
        XCTAssertEqual(call.json?["everywhere"] as? Bool, true)
        XCTAssertNotNil(call.header("Authorization"))
        let signedIn = await auth.isSignedIn
        XCTAssertFalse(signedIn)
        XCTAssertNil(storedSession(storage))
    }

    func testChangePasswordEndsTheLocalSession() async throws {
        Stub.shared.reset { r in
            if r.path.hasSuffix("/signin/password") { return (.json(200, okOutcome()), 0) }
            return (.json(200, ["status": "password_changed", "signed_out": true]), 0)
        }
        let auth = makeClient()
        _ = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        try await auth.changePassword(currentPassword: "pw", newPassword: "new-password-123")
        let signedIn = await auth.isSignedIn
        XCTAssertFalse(signedIn)
    }

    func testSwitchOrganizationRotatesTheRefreshToken() async throws {
        Stub.shared.reset { r in
            if r.path.hasSuffix("/signin/password") { return (.json(200, okOutcome()), 0) }
            XCTAssertEqual(r.json?["org_id"] as? String, "org_2")
            XCTAssertEqual(r.json?["refresh_token"] as? String, "obur_1")
            return (.json(200, ["access_token": TestTokens.accessToken, "expires_in": 900, "refresh_token": "obur_3",
                                "org": ["id": "org_2", "name": "Beta", "roles": ["admin"], "choices": 2]]), 0)
        }
        let storage = InMemoryTokenStorage()
        let auth = makeClient(storage: storage)
        _ = try await auth.signInWithPassword(email: "a@b.c", password: "pw")
        let org = try await auth.switchOrganization("org_2")
        XCTAssertEqual(org?.name, "Beta")
        XCTAssertEqual(storedSession(storage)?["refreshToken"] as? String, "obur_3")
    }

    // MARK: - Hosted sign-in

    private func hostedStub(nonce: String? = nil, tokenFails: Bool = false, browser: @escaping () -> FakeBrowser?) {
        Stub.shared.reset { r in
            if r.path.hasSuffix("/token") {
                if tokenFails { return (.json(400, ["error": "invalid_grant", "error_description": "PKCE verification failed"]), 0) }
                let opened = query(browser()?.opened)
                let form = r.form
                XCTAssertEqual(r.header("Content-Type"), "application/x-www-form-urlencoded")
                XCTAssertEqual(form["grant_type"], "authorization_code")
                XCTAssertEqual(form["code"], "code_1")
                XCTAssertEqual(form["client_id"], testClientId)
                XCTAssertEqual(form["redirect_uri"], testRedirect)
                XCTAssertEqual(PKCE.codeChallenge(for: form["code_verifier"] ?? ""), opened["code_challenge"])
                let idToken = TestTokens.jwt(["iss": testIssuer, "aud": testClientId, "sub": "usr_1",
                                              "nonce": nonce ?? opened["nonce"] ?? ""], typ: "JWT")
                return (.json(200, ["access_token": TestTokens.accessToken, "token_type": "Bearer", "expires_in": 900,
                                    "refresh_token": "obur_5", "id_token": idToken]), 0)
            }
            if r.path.hasSuffix("/api/v1/me") { return (.json(200, userJSON()), 0) }
            return (.json(404, [:]), 0)
        }
    }

    private func browser(callback: String) -> FakeBrowser {
        FakeBrowser { url in
            let state = query(url)["state"] ?? ""
            return URL(string: callback.replacingOccurrences(of: "STATE", with: state))!
        }
    }

    func testHostedSignInChecksAndExchanges() async throws {
        let encodedIssuer = FormEncoding.escape(testIssuer)
        let fake = browser(callback: "\(testRedirect)?code=code_1&state=STATE&iss=\(encodedIssuer)")
        hostedStub { fake }
        let storage = InMemoryTokenStorage()
        let auth = makeClient(storage: storage, browser: fake)

        let user = try await auth.signInWithHostedPage(AuthorizationOptions(provider: "uprov_google", loginHint: "a+b@example.com"))

        XCTAssertEqual(user?.displayName, "Ada")
        let opened = try XCTUnwrap(fake.opened)
        XCTAssertTrue(opened.absoluteString.hasPrefix("\(testIssuer)/authorize?"))
        let q = query(opened)
        XCTAssertEqual(q["response_type"], "code")
        XCTAssertEqual(q["code_challenge_method"], "S256")
        XCTAssertEqual(q["scope"], "openid profile email")
        XCTAssertEqual(q["provider"], "uprov_google")
        XCTAssertEqual(q["login_hint"], "a+b@example.com")
        XCTAssertTrue(opened.absoluteString.contains("login_hint=a%2Bb%40example.com"))
        XCTAssertEqual(storedSession(storage)?["refreshToken"] as? String, "obur_5")
        XCTAssertNil(storage.snapshot["\(testStorageKey).pkce"])

        let logout = await auth.buildLogoutURL(postLogoutRedirectURI: "com.example.app:/signedout", state: "s1")
        let lq = query(logout)
        XCTAssertEqual(lq["client_id"], testClientId)
        XCTAssertEqual(lq["id_token_hint"], storedSession(storage)?["idToken"] as? String)
        XCTAssertEqual(lq["post_logout_redirect_uri"], "com.example.app:/signedout")
    }

    func testHostedSignInRefusesAWrongState() async throws {
        let fake = browser(callback: "\(testRedirect)?code=code_1&state=forged")
        hostedStub { fake }
        let auth = makeClient(browser: fake)
        await expectError("invalid_state") { _ = try await auth.signInWithHostedPage() }
        XCTAssertTrue(Stub.shared.requests(endingWith: "/token").isEmpty)
    }

    func testHostedSignInRefusesAWrongIssuer() async throws {
        let fake = browser(callback: "\(testRedirect)?code=code_1&state=STATE&iss=https%3A%2F%2Fevil.example.com")
        hostedStub { fake }
        let auth = makeClient(browser: fake)
        await expectError("invalid_issuer") { _ = try await auth.signInWithHostedPage() }
        XCTAssertTrue(Stub.shared.requests(endingWith: "/token").isEmpty)
    }

    func testHostedSignInRefusesAWrongNonce() async throws {
        let fake = browser(callback: "\(testRedirect)?code=code_1&state=STATE")
        hostedStub(nonce: "other") { fake }
        let auth = makeClient(browser: fake)
        await expectError("invalid_nonce") { _ = try await auth.signInWithHostedPage() }
        let signedIn = await auth.isSignedIn
        XCTAssertFalse(signedIn)
    }

    func testHostedSignInSurfacesErrors() async throws {
        let denied = browser(callback: "\(testRedirect)?error=access_denied&error_description=denied&state=STATE")
        hostedStub { denied }
        await expectError("access_denied") { _ = try await makeClient(browser: denied).signInWithHostedPage() }

        let failing = browser(callback: "\(testRedirect)?code=code_1&state=STATE")
        hostedStub(tokenFails: true) { failing }
        await expectError("invalid_grant") { _ = try await makeClient(browser: failing).signInWithHostedPage() }
    }

    func testPKCEChallengeMatchesRFC7636() {
        // RFC 7636 appendix B.
        XCTAssertEqual(PKCE.codeChallenge(for: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
                       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        XCTAssertTrue(PKCE.constantTimeEquals("abc", "abc"))
        XCTAssertFalse(PKCE.constantTimeEquals("abc", "abd"))
        XCTAssertFalse(PKCE.constantTimeEquals("abc", "abcd"))
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func increment() {
        lock.lock()
        count += 1
        lock.unlock()
    }
}

final class StateRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [AuthState] = []

    var values: [AuthState] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    func append(_ state: AuthState) {
        lock.lock()
        recorded.append(state)
        lock.unlock()
    }
}
