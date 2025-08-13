//
// Copyright contributors to the IBM Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// The `ISVAUserService` for issuing and validating one-time passwords and creating a new user on IBM Verify Access.
///
/// - Remark: IBM Verify Access has a number of confguration options to support one-time password generation, validation and user account creation.  The methods are placeholders to suit the ISVA environment.
class ISVAUserService: UserService {
    /// Core type representing a Vapor application.
    let webApp: Application
    
    /// The base ``URL`` for the host.
    let baseURL: URL
    
    /// Initialize the user service.
    /// - Parameters:
    ///   - webApp: Core type representing a Vapor application.
    ///   - baseURL: The base ``URL`` for the host.
    required init(_ webApp: Application, baseURL: URL) {
        webApp.logger.debug("init Entry")
        
        defer {
            webApp.logger.debug("init Exit")
        }
        
        self.webApp = webApp
        self.baseURL = baseURL.appendingPathComponent("/v2.0")
        self.webApp.logger.debug("Base URL for token service is: \(self.baseURL.absoluteString)")
    }
    
    /// Generate an one-time password to be emailed.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - email: The user's email address
    func generateOTP(token: Token, email: String) async throws -> OTPChallenge {
        throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Method not implemented.")
    }
    
    
    /// Verify a one-time password associated with the user sign-up operation.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - transactionId: The specific verification identifier.
    ///   - oneTimePassword: The one-time password value
    ///   - user: The use's sign-up details.
    func verifyUser(token: Token, transactionId: String, oneTimePassword: String, user: UserSignUp) async throws -> String {
        throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Method not implemented.")
    }
    
    /// Create a new user in IBM Verify Access.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - email: The user's email address.
    ///   - name: The users' first and last name.
    internal func createUser(token: Token, email: String, name: String) async throws -> String {
        throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Method not implemented.")
    }
}
