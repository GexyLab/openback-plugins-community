import Foundation

extension URLSession {
    /// Sends `request` with `Authorization: Bearer <access token>` from `client` (renewed when needed).
    ///
    /// ```swift
    /// let (data, response) = try await URLSession.shared.data(for: URLRequest(url: ordersURL), authorizedBy: auth)
    /// ```
    ///
    /// Send it only to your own API: the token grants access to the user's data.
    public func data(for request: URLRequest, authorizedBy client: AppAuthClient) async throws -> (Data, URLResponse) {
        let authorized = try await client.authorize(request)
        return try await data(for: authorized)
    }

    /// Uploads `body` with `Authorization: Bearer <access token>` from `client`.
    public func upload(for request: URLRequest, from body: Data, authorizedBy client: AppAuthClient) async throws -> (Data, URLResponse) {
        let authorized = try await client.authorize(request)
        return try await upload(for: authorized, from: body)
    }
}
