//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// The `ISVWebAuthnService` for issuing challenges to an authenticator and performing attestation and assertion requests.
class ISVWebAuthnService: WebAuthnService {
    /// Core type representing a Vapor application.
    let webApp: Application
    
    /// The base ``URL`` for the host.
    let baseURL: URL
    
    /// Initialize the Webauthn service.
    /// - Parameters:
    ///   - webApp: Core type representing a Vapor application.
    ///   - baseURL: The base ``URL`` for the host.
    ///   - relyingPartyId: The UUID representing the unique relying party.
    required init(_ webApp: Application, baseURL: URL, relyingPartyId: String) {
        self.webApp = webApp
        self.baseURL = baseURL.appendingPathComponent("/v2.0/factors/fido2/relyingparties/\(relyingPartyId)")
    }
    
    func verifyCredentail(token: Token, clientDataJSON: String, authenticatorData: String, credentialId: String, signature: String, userHandle: String) async throws -> Data {
        let response = try await self.webApp.client.post(URI(stringLiteral: self.baseURL.absoluteString + "/assertion/result?returnJwt=true")) { request in
            
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
}
