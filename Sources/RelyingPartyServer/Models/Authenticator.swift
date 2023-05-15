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

protocol PublicKeyCredentialOptions {
    /// In milliseconds, indicates the time the calling client is willing to wait for the creation operation to complete.
    var timeout: Int? {
        get
    }
    
    /// A string provided by the relying party's server and used as a cryptographic challenge and will be signed by the authenticator.
    var challenge: String {
        get
    }
}

/// An object used to supply options when retrieving an existing credential.
struct PublicKeyCredentialGetOptions: PublicKeyCredentialOptions, Content {
    /// A string that specifies the relying party's identifier.
    let rpId: String?
    let timeout: Int?
    let challenge: String
    
    ///An array of objects defining a restricted list of the acceptable credentials for retrieval.
    let allowCredentials: [AllowCredential]?
    
    /// An object containing properties representing the input values for any requested extensions. These extensions are used to specific additional processing by the client or authenticator during the authentication process.
    let extensions: Extensions?
    
    struct AllowCredential: Content {
        /// A string representing the ID of the public key credential to retrieve.
        let id: String
        
        /// A string defining the type of the public key credential to retrieve. This can currently take a single value, `"public-key"`.
        let type: String
    }
    
    struct Extensions: Content {
    }
}

/// An object used to supply options when creating a new credential.
struct PublicKeyCredentialCreationOptions: PublicKeyCredentialOptions, Content {
    /// An object describing the relying party that requested the credential creation.
    let rp: Rp
    
    /// An object describing the user account for which the credential is generated.
    let user: User

    let timeout: Int?
    
    let challenge: String
    
    /// An Array of objects describing existing credentials that are already mapped to this user account.
    let excludeCredentials: [ExcludeCredential]?
    
    /// An object containing properties representing the input values for any requested extensions. These extensions are used to specific additional processing by the client or authenticator during the credential creation process.
    let extensions: Extensions?
    
    /// An object whose properties are criteria used to filter out the potential authenticators for the credential creation operation.
    let authenticatorSelection: AuthenticatorSelection?
    
    /// An Array of objects which specify the key types and signature algorithms the Relying Party supports, ordered from most preferred to least preferred. The client and authenticator will make a best-effort to create a credential of the most preferred type possible.
    let pubKeyCredParams: [PubKeyCredParam]
    
    struct AuthenticatorSelection: Content {
        /// A boolean. If set to `true`, it indicates that a resident key is required.
        let requireResidentKey: Bool
        
        /// A string indicating which authenticator attachment type should be permitted for the chosen authenticator.
        let authenticatorAttachment: String
        
        /// A string that specifies the relying party's requirements for user verification for the `create()` operation.
        let userVerification: String
    }

    struct ExcludeCredential: Content {
        /// A string representing the existing credential ID.
        let id: String
        
        /// A string defining the type of public key credential to create.  This can currently take a single value, `"public-key"`.
        let type: String
    }

    struct Extensions: Content {
    }

    struct PubKeyCredParam: Content {
        /// A number that is equal to a COSE Algorithm Identifier, representing the cryptographic algorithm to use for this credential type.
        let alg: Int
        
        /// A string defining the type of public key credential to create. This can currently take a single value, `"public-key"`.
        let type: String
    }

   struct Rp: Content {
        /// A string representing the ID of the relying party. A public key credential can only be used for authentication with the same relying party.
        let id: String
        
        /// A string representing the name of the relying party.
        let name: String
    }

    /// An object describing the user account for which the credential is generated.
    struct User: Content {
        /// A  unique ID for the user account.
        let id: String
        
        /// A string providing a human-friendly identifier for the user's account, to help distinguish between different accounts.
        let name: String
        
        /// A string providing a human-friendly user display name, which will have been set by user during initial registration with the relying party.
        let displayName: String
    }
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
