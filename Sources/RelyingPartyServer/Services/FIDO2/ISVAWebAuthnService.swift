//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// The `ISVAWebAuthnService` for issuing challenges to an authenticator and performing attestation and assertion requests.
class ISVAWebAuthnService: WebAuthnService {
    /// Core type representing a Vapor application.
    let webApp: Application
    
    /// The base ``URL`` for the host.
    let baseURL: URL
    
    /// Initialize the Webauthn service.
    /// - Parameters:
    ///   - webApp: Core type representing a Vapor application.
    ///   - baseURL: The base ``URL`` for the host.
    ///   - relyingPartyId: The UUID representing the unique relying party.
    ///
    /// The default path to the FIDO2 endpoints is:
    ///
    /// `/<aac_junction>/sps/fido2/<relying_party_identifier>`
    required init(_ webApp: Application, baseURL: URL, relyingPartyId: String) {
        self.webApp = webApp
        self.baseURL = baseURL.appendingPathComponent("/mga/sps/fido2/\(relyingPartyId)")
    }
    
    func generateChallenge(token: Token, displayName: String?, type: ChallengeType) async throws -> FIDO2Challenge {
        // Set the JSON request body.
        var body = "{"
        if let displayName = displayName {
            body += "\"displayName\": \"\(displayName)\""
        }
        
        if type == .assertion {
            body += "\"username\": \"\""
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
