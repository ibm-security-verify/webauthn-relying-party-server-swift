//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// A structure that represents a user's authentication infomration.
struct UserAuthentication: Content, Validatable {
    /// The user's username.
    let username: String

    /// The users' password.
    let password: String
    
    static func validations(_ validations: inout Validations) {
        validations.add("username", as: String.self, is: .email || .alphanumeric)
        validations.add("password", as: String.self, is: .count(5...))
    }
}

/// A structure that represents a user's sign-up infomration.
struct UserSignUp: Content, Validatable {
    /// The users' first and last name.
    let name: String
    
    /// The user's email address.
    let email: String

    static func validations(_ validations: inout Validations) {
        validations.add("name", as: String.self, is: .count(1...))
        validations.add("email", as: String.self, is: .email)
    }
}

/// A structure that describes a one-time password challenge.
struct OTPChallenge: Content {
    /// The unique identifier of the verification.
    let transactionId: String
    
    /// A value to be associated with the verification. It will be prefixed to the one-time password in the email to be sent.
    let correlation: String
    
    /// The time when the verification expires.
    let expiry: Date
    
    private enum CodingKeys: String, CodingKey {
        case transactionId = "id"
        case correlation
        case expiry
    }
}

/// A strucutre that describes a one-time password verification.
struct OTPVerification: Content, Validatable {
    /// The unique identifier of the verification
    let transactionId: String
    
    /// The one-time password value.
    let otp: String

    static func validations(_ validations: inout Validations) {
        validations.add("transactionId", as: String.self, is: !.empty)
        validations.add("otp", as: String.self, is: !.empty)
    }
}

/// A structure that represents a user's account.
struct UserAccount: Authenticatable {
    /// The unique identifier of the user account.
    let id: String
    
    /// The name of the user.
    let name: String
}
