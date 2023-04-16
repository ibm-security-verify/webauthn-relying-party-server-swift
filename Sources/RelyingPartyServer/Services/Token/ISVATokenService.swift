//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// The `ISVATokenService` obtains a new OAuth token from the IBM Security Verify Access authorization server.
class ISVATokenService: TokenService {
    let baseURL: URL
    let clientId: String
    let clientSecret: String
    let webApp: Application
    
    required init(_ webApp: Application, baseURL: URL, clientId: String, clientSecret: String) {
        self.webApp = webApp
        self.baseURL = baseURL.appendingPathComponent("/mga/sps/oauth/oauth20/token")
        self.clientId = clientId
        self.clientSecret = clientSecret
    }
    
    /// Authorize an application client credentials using jwt-bearer grant type returning an OIDC token.
    /// - Parameters:
    ///   - assertion: The  JSON web token assertion to be exchanged.
    /// - Returns: An instance of a ``Token``.
    func jwtBearer(assertion: String) async throws -> Token {
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString)) { request in
            request.headers.contentType = .urlEncodedForm
            request.headers.basicAuthorization = BasicAuthorization(username: self.clientId, password: self.clientSecret)
            request.body = ByteBuffer(string: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&scope=openid&assertion=\(assertion)")
        }
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code), let body = response.body {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason: String(buffer: body))
        }
        
        // Get the token_type and access_token values.
        return try response.content.decode(Token.self)
    }
}
