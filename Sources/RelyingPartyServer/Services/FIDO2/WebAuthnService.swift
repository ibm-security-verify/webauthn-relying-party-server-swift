//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// The `WebAuthnService` for issuing challenges to an authenticator and performing attestation and assertion requests.
protocol WebAuthnService {
    /// Core type representing a Vapor application.
    var webApp: Application { get }
    
    /// The base ``URL`` for the host.
    var baseURL: URL { get }
    
    /// Initialize the Webauthn service.
    /// - Parameters:
    ///   - webApp: Core type representing a Vapor application.
    ///   - baseURL: The base ``URL`` for the host.
    ///   - relyingPartyId: The UUID representing the unique relying party.
    init(_ webApp: Application, baseURL: URL, relyingPartyId: String)
    
    /// Verify an authenticator with a signed challenge to the server for verification.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - clientDataJSON: The base64Url-encoded clientDataJson that was received from the WebAuthn client.
    ///   - authenticatorData: Information about the authentication that was produced by the authenticator and verified by the signature.
    ///   - credentialId: The credential identifier that is received from the WebAuthn client.
    ///   - signature: The base64Url-encoded bytes of the signature of the challenge data that was produced by the authenticator.
    ///   - userHandle: The userId provided when creating this credential.
    /// - Returns: A JSON payload that contains the successful verification.
    func verifyCredentail(token: Token, clientDataJSON: String, authenticatorData: String, credentialId: String, signature: String, userHandle: String) async throws -> Data
    
    /// Initiate a FIDO verification with authentication preferences for the challenge.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - displayName: The display name used by the authenticator for UI representation.
    /// - Returns: The unique challenge used as part of this authentication attempt.
    func generateChallenge(token: Token, displayName: String?, type: ChallengeType) async throws -> FIDO2Challenge
}

extension WebAuthnService {
    func verifyCredentail(token: Token, clientDataJSON: String, authenticatorData: String, credentialId: String, signature: String, userHandle: String) async throws -> Data {
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString + "/assertion/result")) { request in
            
            request.headers.contentType = .json
            request.headers.add(name: "Accept", value: HTTPMediaType.json.serialize())
            request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
            request.body = ByteBuffer(string: """
                {
                   "type": "public-key",
                   "id": "\(credentialId)",
                   "rawId": "\(credentialId)",
                   "response": {
                       "clientDataJSON": "\(clientDataJSON)",
                       "authenticatorData": "\(authenticatorData)",
                       "signature": "\(signature)",
                       "userHandle": "\(userHandle)"
                   }
                }
            """)
        }
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code), let body = response.body {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason: String(buffer: body))
        }
        
        // Get the data from the reponse body.
        guard let body = response.body else {
            throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Unable to obtain assertion result response data.")
        }
        
        return Data(buffer: body)
    }
    
    /// Create a new authenticator with an attestation object containing a public key for server verification and storage.
    /// - Parameters:
    ///   - token: The ``Token`` for authorizing requests to back-end services.
    ///   - nickname: The friendly name for the registration.
    ///   - clientDataJSON: The base64Url-encoded clientDataJSON that is received from the WebAuthn client.
    ///   - attestationObject: The base64Url-encoded attestationObject that is received from the WebAuthn client.
    ///   - credentialId: The credential identifier that is received from the WebAuthn client.
    func createCredentail(token: Token, nickname: String, clientDataJSON: String, attestationObject: String, credentialId: String) async throws {
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString + "/attestation/result")) { request in
            request.headers.contentType = .json
            request.headers.add(name: "Accept", value: HTTPMediaType.json.serialize())
            request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
            request.body = ByteBuffer(string: """
                {
                    "type": "public-key",
                    "enabled": "true",
                    "id": "\(credentialId)",
                    "rawId": "\(credentialId)",
                    "nickname": "\(nickname)",
                    "response": {
                        "clientDataJSON": "\(clientDataJSON)",
                        "attestationObject": "\(attestationObject)"
                    }
                }
            """)
        }
                                                
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code), let body = response.body {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason: String(buffer: body))
        }
    }

    func generateChallenge(token: Token, displayName: String?, type: ChallengeType) async throws -> FIDO2Challenge {
        // Set the JSON request body.
        var body = "{"
        if let displayName = displayName {
            body += "\"displayName\": \"\(displayName)\""
        }
        body += "}"
        
        print("Challenge Request body \(body)")
        
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString + "/\(type.rawValue)/options")) { request in
            request.headers.contentType = .json
            request.headers.add(name: "Accept", value: HTTPMediaType.json.serialize())
            request.headers.bearerAuthorization = BearerAuthorization(token: token.accessToken)
            request.body = ByteBuffer(string: body)
        }
       
        print("Challenge Response body \(String(buffer: response.body!))")
        
        // Check the response status for 200 range.
        if !(200...299).contains(response.status.code), let body = response.body {
            throw Abort(HTTPResponseStatus(statusCode: Int(response.status.code)), reason: String(buffer: body))
        }
        
        // Get FIDO2 challenge.
        guard let body = response.body, let json = try JSONSerialization.jsonObject(with: body, options: []) as? [String: Any], let challenge = json["challenge"] as? String else {
            throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Unable to parse FIDO2 challenge.")
        }
        
        // If an attestation challenge, parse the user element with the id, name and displayName.
        if type == .assertion {
            return FIDO2Challenge(challenge: challenge, userId: nil, name: nil, displayName: nil)
        }
        
        guard let body = response.body, let json = try JSONSerialization.jsonObject(with: body, options: []) as? [String: Any], let user = json["user"] as? [String: Any], let userId = user["id"] as? String, let name = user["name"] as? String, let displayName = user["displayName"] as? String else {
            throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Unable to parse FIDO2 user element in the JSON payload.")
        }
        
        return FIDO2Challenge(challenge: challenge, userId: userId, name: name, displayName: displayName)
    }
}

/// The type of FIDO2 challenge.
enum ChallengeType: String, Codable {
    /// To attest to the provenance of an authenticator.
    case attestation
    
    /// To assert a cryptographically signed object returned by an authenticator.
    case assertion
}
