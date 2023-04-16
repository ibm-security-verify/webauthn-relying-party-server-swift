//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// Represents an access token.
struct Token: Content {
    /// The access token that is issued by the authorization server.
    let accessToken: String
    
    /// The type of the access token.
    ///
    /// Default is `Bearer`.
    let tokenType: String
    
    /// The lifetime, in seconds, of the access token.
    ///
    /// Default is `3600`.
    let expiry: Int
    
    /// An artifact that proves that the user has been authenticated.
    ///
    /// Default is `nil`.
    let idToken: String?
    
    /// Initializes the Token structure..
    /// - Parameters:
    ///   - accessToken: The access token that is issued by the authorization server.
    init(accessToken: String) {
        self.accessToken = accessToken
        self.tokenType = "Bearer"
        self.expiry = 3600
        self.idToken = nil
    }
    
    /// The HTTP authorization header value for requests to an OpenID Connect service.
    ///
    /// The value combines the `tokenType` and `accessToken` as follows:
    /// ```
    /// Bearer a1b2c3d4
    /// ```
    var authorizationHeader: String {
        return "\(tokenType) \(accessToken)"
    }
    
    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiry = "expires_in"
        case idToken = "id_token"
    }
}
