//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// The `ISVUserService` for issuing and validating one-time passwords and creating a new user on IBM Security Verify.
class ISVUserService: UserService {
    /// Core type representing a Vapor application.
    let webApp: Application
    
    /// The base ``URL`` for the host.
    let baseURL: URL
    
    /// Initialize the user service.
    /// - Parameters:
    ///   - webApp: Core type representing a Vapor application.
    ///   - baseURL: The base ``URL`` for the host.
    required init(_ webApp: Application, baseURL: URL) {
        self.webApp = webApp
        self.baseURL = baseURL.appendingPathComponent("/v2.0")
    }
    
    /// Generate an one-time password to be emailed.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - email: The user's email address
    func generateOTP(token: Token, email: String) async throws -> OTPChallenge {
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString + "/factors/emailotp/transient/verifications")) { request in
            request.headers.contentType = .json
            request.headers.add(name: "accept", value: HTTPMediaType.json.serialize())
            request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
            try request.content.encode(["emailAddress": "\(email)"])
        }
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code), let body = response.body {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason: String(buffer: body))
        }
        
        // Convert the date to custom ISO8601 format.
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(DateFormatter.iso8061FormatterBehavior)
        
        self.webApp.logger.info("OTP for '\(email)' generated successfully.")
        
        return try response.content.decode(OTPChallenge.self, using: decoder)
    }
    
    
    /// Verify a one-time password associated with the user sign-up operation.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - transactionId: The specific verification identifier.
    ///   - oneTimePassword: The one-time password value
    ///   - user: The use's sign-up details.
    func verifyUser(token: Token, transactionId: String, oneTimePassword: String, user: UserSignUp) async throws -> String {
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString + "/factors/emailotp/transient/verifications/\(transactionId)")) { request in
            request.headers.contentType = .json
            request.headers.add(name: "Accept", value: HTTPMediaType.json.serialize())
            request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
            try request.content.encode(["otp": "\(oneTimePassword)"])
        }
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code), let body = response.body {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason: String(buffer: body))
        }
        
        self.webApp.logger.info("OTP identifier '\(transactionId)' validated successfully.")
        
        // Create the user.
        return try await createUser(token: token, email: user.email, name: user.name)
    }
    
    /// Create a new user in IBM Security Verify.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - email: The user's email address.
    ///   - name: The users' first and last name.
    internal func createUser(token: Token, email: String, name: String) async throws -> String {
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString + "/Users")) { request in
            request.headers.contentType = HTTPMediaType(type: "application", subType: "scim+json")
            request.headers.add(name: "Accept", value: HTTPMediaType(type: "application", subType: "scim+json").serialize())
            request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
            request.body = ByteBuffer(string: """
                {
                   "userName": "\(email)",
                   "name": {
                      "givenName": "\(name)"
                   },
                   "urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification": {
                      "notifyType": "EMAIL",
                      "notifyPassword": false
                   },
                   "urn:ietf:params:scim:schemas:extension:ibm:2.0:User": {
                      "realm": "cloudIdentityRealm",
                      "userCategory": "regular",
                      "twoFactorAuthentication": false
                   },
                   "active": true,
                   "emails": [{
                        "type": "work",
                        "value": "\(email)"
                   }],
                   "schemas": [
                      "urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification",
                      "urn:ietf:params:scim:schemas:extension:ibm:2.0:User",
                      "urn:ietf:params:scim:schemas:core:2.0:User"
                   ]
                }
            """)
        }
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code), let body = response.body {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason: String(buffer: body))
        }
        
        // Get owner id.
        guard let body = response.body, let json = try JSONSerialization.jsonObject(with: body, options: []) as? [String: Any], let userId = json["id"] as? String else {
            throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Unable to parse user identifer.")
        }
        
        self.webApp.logger.info("User created with identifier '\(userId)'.")
        
        return userId
    }
}
