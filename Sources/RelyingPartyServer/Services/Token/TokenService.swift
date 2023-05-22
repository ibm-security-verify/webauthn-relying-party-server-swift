//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// The `TokenService` obtains a new OAuth token from an authorization server.
protocol TokenService {
    /// The base ``URL`` for the host.
    var baseURL: URL { get }
    
    /// The client identifier issued to the client for performing operations on behalf of a user.
    var clientId: String { get }
    
    /// The client secret.
    var clientSecret: String { get }
    
    /// Core type representing a Vapor application.
    var webApp: Application { get }
    
    /// Initialize the token service.
    /// - Parameters:
    ///   - webApp: Core type representing a Vapor application.
    ///   - baseURL: The base ``URL`` for the host.
    ///   - clientId: The client identifier issued to the client for performing operations on behalf of a user.
    ///   - clientSecret: The client secret.
    init(_ webApp: Application, baseURL: URL, clientId: String, clientSecret: String)
    
    /// Authorize an application client credentials using jwt-bearer grant type returning an OIDC token.
    /// - Parameters:
    ///   - assertion: The  JSON web token assertion to be exchanged.
    /// - Returns: An instance of a ``Token``.
    func jwtBearer(assertion: String) async throws -> Token
}

extension TokenService {
    /// Authorize an API client credentials grant type returning an OIDC token
    /// - Returns: An instance of a ``Token``.
    func clientCredentials() async throws -> Token {
        webApp.logger.debug("clientCredentials Entry")
        
        defer {
            webApp.logger.debug("clientCredentials Exit")
        }
        
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString)) { request in
            request.headers.contentType = .urlEncodedForm
            request.body = ByteBuffer(string: "client_id=\(self.clientId)&client_secret=\(self.clientSecret)&grant_type=client_credentials")
            
            webApp.logger.debug("Request body:\n\(String(buffer: request.body!))")
        }
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code), let body = response.body {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason: String(buffer: body))
        }
        
        // Get the token_type and access_token values.
        return try response.content.decode(Token.self)
    }
    
    /// Authorize an application client credentials using resource owner password credential (ROPC) grant type, returning an OIDC token.
    /// - Parameters:
    ///   - username: The user's username.
    ///   - password: The users' password.
    /// - Returns: An instance of a ``Token``.
    func password(username: String, password: String) async throws -> Token {
        webApp.logger.debug("password Entry")
        
        defer {
            webApp.logger.debug("password Exit")
        }
        
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString)) { request in
            request.headers.contentType = .urlEncodedForm
            request.body = ByteBuffer(string: "client_id=\(self.clientId)&client_secret=\(self.clientSecret)&grant_type=password&username=\(username)&password=\(password)&scope=openid")
            
            webApp.logger.debug("Request body:\n\(String(buffer: request.body!))")
        }
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code), let body = response.body {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason: String(buffer: body))
        }
        
        // Get the token_type and access_token values.
        return try response.content.decode(Token.self)
    }
    
    /// Generates a JSON web token (JWT) for validating against the token endpoint.
    /// - Parameters:
    ///   - signingSecret: The secret to use to generate a signing key.
    ///   - subject: The subject identifies the principal that is the subject of the JWT.
    ///   - issuer:  The issuer identifies the principal that issued the JWT.
    /// - Returns: A string representing the JWT.
    ///
    ///   The signature is generated using HMAC SHA256.
    func generateJWT(signingSecret: String, subject: String, issuer: String) -> String {
        return Self.generateJWT(self.baseURL, signingSecret: signingSecret, subject: subject, issuer: issuer)
    }
    
    /// Generates a JSON web token (JWT) for validating against the token endpoint.
    /// - Parameters:
    ///   - baseURL: The base ``URL`` for the host.
    ///   - signingSecret: The secret to use to generate a signing key.
    ///   - subject: The subject identifies the principal that is the subject of the JWT.
    ///   - issuer:  The issuer identifies the principal that issued the JWT.
    /// - Returns: A string representing the JWT.
    ///
    ///   The signature is generated using HMAC SHA256.
    public static func generateJWT(_ baseURL: URL, signingSecret: String, subject: String, issuer: String) -> String {
        // Construct the JWT header
        let headerDict: [String: String] = [
            "alg": "HS256",
            "typ": "JWT"
        ]
        let header = try! JSONSerialization.data(withJSONObject: headerDict, options: [])

        // Construct the JWT body
        let bodyDict: [String: Any] = [
            "sub": "\(subject)",
            "iat": Int(UInt64(Date().timeIntervalSince1970)),
            "exp": Int(UInt64(Date().advanced(by: 3600).timeIntervalSince1970)),
            "iss": "\(issuer)",
            "aud": "\(baseURL)",
            "jti": "\(UUID().uuidString)"
        ]
        let body = try! JSONSerialization.data(withJSONObject: bodyDict, options: [])
        
        let key = SymmetricKey(data: Data(signingSecret.utf8))

        // Create the header.
        let headerBase64String = header.base64UrlEncodedString(options: .noPaddingCharacters)
        
        // Create the payload.
        let payloadBase64String = body.base64UrlEncodedString(options: .noPaddingCharacters)

        let dataToSign = Data((headerBase64String + "." + payloadBase64String).utf8)
        
        // Generate the signature.
        let signature = HMAC<SHA256>.authenticationCode(for: dataToSign, using: key)
        
        let signatureBase64String = Data(signature).base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters])

        // Return the JWT as a string.
        return [headerBase64String, payloadBase64String, signatureBase64String].joined(separator: ".")
    }
}
