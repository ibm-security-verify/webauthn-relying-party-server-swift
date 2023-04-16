//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// The `UserService` for issuing and validating one-time passwords and creating a new user.
protocol UserService {
    /// Core type representing a Vapor application.
    var webApp: Application { get }
    
    /// The base ``URL`` for the host.
    var baseURL: URL {get }
    
    /// Initialize the user service.
    /// - Parameters:
    ///   - webApp: Core type representing a Vapor application.
    ///   - baseURL: The base ``URL`` for the host.
    init(_ webApp: Application, baseURL: URL)
    
    /// Generate an one-time password to be emailed.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - email: The user's email address
    func generateOTP(token: Token, email: String) async throws -> OTPChallenge
    
    
    /// Verify a one-time password associated with the user sign-up operation.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - transactionId: The specific verification identifier.
    ///   - oneTimePassword: The one-time password value
    ///   - user: The use's sign-up details.
    func verifyUser(token: Token, transactionId: String, oneTimePassword: String, user: UserSignUp) async throws -> String
    
    /// Create a new user.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - email: The user's email address.
    ///   - name: The users' first and last name.
    func createUser(token: Token, email: String, name: String) async throws -> String
}
