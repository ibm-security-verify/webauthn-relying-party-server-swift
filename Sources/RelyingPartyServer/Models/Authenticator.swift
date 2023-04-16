//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// A structure that represents a WebAuthn challenge request.
///
/// This structure is used for both registration (attetation) and sign-in (assertion) requests.
struct ChallengeRequest: Content {
    /// The display name used by the authenticator for UI representation.
    let displayName: String?
    
    /// The type of FIDO2 challenge.
    let type: ChallengeType
}

/// A structure representing a FIDO2 challenge.
struct FIDO2Challenge: Content {
    /// The unique challenge that is used as part of this attestation or assertion attempt.
    let challenge: String
    
    /// The unique identifier of the user account.
    ///
    /// The value is only provided for an attestation challenge, otherwise `nil`.
    let userId: String?
    
    /// The name of the user requesting the challenge.
    ///
    /// The value is only provided for an attestation challenge, otherwise `nil`.
    let name: String?
    
    /// The display name of the user requesting the challenge.
    ///
    /// The value is only provided for an attestation challenge, otherwise `nil`.
    let displayName: String?
}

/// A structure representing a FIDO2 registration.
struct FIDO2Registration: Content, Validatable {
    /// The friendly name for the registration.
    let nickname: String
    
    /// The base64Url-encoded clientDataJSON that is received from the WebAuthn client.
    let clientDataJSON: String
    
    /// The base64Url-encoded attestationObject that is received from the WebAuthn client.
    let attestationObject: String
    
    /// The credential identifier that is received from the WebAuthn client.
    ///
    /// The string is Base64 URL encoded with URL safe characters.
    let credentialId: String

    static func validations(_ validations: inout Validations) {
        validations.add("nickname", as: String.self, is: !.empty)
        validations.add("clientDataJSON", as: String.self,  is: .valid)
        validations.add("attestationObject", as: String.self, is: .valid)
        validations.add("credentialId", as: String.self, is: .valid)
    }
}

/// A structure representing a FIDO2 verification.
struct FIDO2Verification: Content, Validatable {
    /// The base64Url-encoded clientDataJson that was received from the WebAuthn client.
    let clientDataJSON: String
    
    /// Information about the authentication that was produced by the authenticator and verified by the signature.
    let authenticatorData: String
    
    /// The credential identifier that is received from the WebAuthn client.
    ///
    /// The string is Base64 URL encoded with URL safe characters.
    let credentialId: String
    
    /// The base64Url-encoded bytes of the signature of the challenge data that was produced by the authenticator.
    let signature: String

    /// The userId provided when creating this credential.
    let userHandle: String
    
    static func validations(_ validations: inout Validations) {
        validations.add("clientDataJSON", as: String.self,  is: !.empty)
        validations.add("authenticatorData", as: String.self, is: !.empty)
        validations.add("signature", as: String.self, is: !.empty)
        validations.add("credentialId", as: String.self, is: !.empty)
        validations.add("userHandle", as: String.self, is: !.empty)
    }
}
