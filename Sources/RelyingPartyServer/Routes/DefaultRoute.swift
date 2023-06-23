//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

///  A platform supported by the relying party service.
enum Platform: String, Equatable {
    /// IBM Security Verify
    case isv
    
    /// IBM Security Verify Access
    case isva
}

///  The IBM Security Verify Access authenticated session type.
enum ISVAAuthSession: String, Equatable {
    /// Cookies representing an authenticsted session
    case cookies
    
    /// External Authentication Interface (EAI)  headers
    case eai
    
    /// An OAuth token.
    case token
}

/// The default route controller that processes requests to manage user sign-up, registration and sign-in processes.
struct DefaultRoute: RouteCollection {
    private let webAuthnService: WebAuthnService
    private let userService: UserService
    private let authTokenService: TokenService
    private let apiTokenService: TokenService
    private let webApp: Application
    private let platform: Platform
    private var authSession: ISVAAuthSession = .token
    
    // Reserved headers.
    private let reservedHeaders = ["content-length",
                                   "authorization",
                                   "connection",
                                   "host",
                                   "accept-encoding",
                                   "proxy-authenticate",
                                   "proxy-authorization",
                                   "www-authenticate"]
    
    /// Initializes the default routes for user interactions.
    /// - Parameters:
    ///   - webApp: Core type representing a Vapor application.
    init(_ webApp: Application) throws {
        webApp.logger.debug("init Entry")
        
        defer {
            webApp.logger.debug("init Exit")
        }
        
        // Load the base URL for interacting with the services.
        guard let platformValue = Environment.get("PLATFORM"), let platform = Platform(rawValue: platformValue.lowercased()) else {
            fatalError("The platform environment variable not set or invalid. Valid PLATFORM values are 'ISV' or 'ISVA'.")
        }
        
        // Load the base URL for interacting with the services.
        guard let base = Environment.get("BASE_URL"), let baseURL = URL(string: base) else {
            fatalError("The base URL environment variables not set or invalid.")
        }
        
        guard let relyingPartyId = Environment.get("FIDO2_RELYING_PARTY_ID") else {
            fatalError("The relying party identifier is not set or invalid.")
        }
        
        guard let apiClientId = Environment.get("API_CLIENT_ID"), let apiClientSecret = Environment.get("API_CLIENT_SECRET") else {
            fatalError("FIDO2 related environment variables not set or invalid.")
        }
        
        // If not provided, then the /authenticate, /signup and /validate endpoints will return a 400 Bad Request response.
        guard let authClientId = Environment.get("AUTH_CLIENT_ID"), let authClientSecret = Environment.get("AUTH_CLIENT_SECRET") else {
            fatalError("User authenticaton related environment variables not set or invalid.")
        }
        
        if platform == .isva, let authSessionValue = Environment.get("AUTH_SESSION"), let authSession = ISVAAuthSession(rawValue: authSessionValue.lowercased()) {
            webApp.logger.notice(Logger.Message(stringLiteral: "Server configured for \(authSession.rawValue) as the signin response from \(platform.rawValue)"))
            self.authSession = authSession
        }
        
        // Create instances of services for Token (authorization of users and api clients), users and FIDO WebAuthn.
        switch platform {
        case .isv:
            self.userService = ISVUserService(webApp, baseURL: baseURL)
            self.webAuthnService = ISVWebAuthnService(webApp, baseURL: baseURL, relyingPartyId: relyingPartyId)
            self.authTokenService = TokenService(webApp, baseURL: baseURL.appendingPathComponent("/v1.0/endpoint/default/token"), clientId: authClientId, clientSecret: authClientSecret)
            self.apiTokenService = TokenService(webApp, baseURL: baseURL.appendingPathComponent("/v1.0/endpoint/default/token"), clientId: apiClientId, clientSecret: apiClientSecret)
        case .isva:
            self.userService = ISVAUserService(webApp, baseURL: baseURL)
            self.webAuthnService = ISVAWebAuthnService(webApp, baseURL: baseURL, relyingPartyId: relyingPartyId)
            self.authTokenService = TokenService(webApp, baseURL: baseURL.appendingPathComponent("/mga/sps/oauth/oauth20/token"), clientId: authClientId, clientSecret: authClientSecret)
            self.apiTokenService = TokenService(webApp, baseURL: baseURL.appendingPathComponent("/mga/sps/oauth/oauth20/token"), clientId: apiClientId, clientSecret: apiClientSecret)
        }
        
        self.platform = platform
        self.webApp = webApp
        
        self.webApp.logger.notice("Configured for \(platform.rawValue.uppercased())")
    }
    
    func boot(routes: RoutesBuilder) throws {
        // Returns a simply string to indicate the relying party is running.
        webApp.routes.get { _ in
            return "Welcome to IBM Security Verify Relying Party Server for Swift"
        }
        
        let route = routes.grouped("v1")
        // Used for existing accounts with a password resulting in an ROPC to token endpoint.
        route.post("authenticate", use: authenticate)
        
        // Used to initiate a user sign-up, which also requires the OTP validation.
        route.post("signup", use: signup)
        route.post("validate", use: validate)
        
        // Used to generate a FIDO challenge for attestation and assertion.
        route.post("challenge", use: challenge)
        
        // Used to register an authenticatpr with a FIDO attestation result.
        route.post("register", use: register)
        
        // Used to validate an authenticator with a FIDO assertion result.
        route.post("signin", use: signin)
    }
}

// MARK: Endpoint Handlers
extension DefaultRoute {
    /// The user authentication request.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    /// - Returns: A ``Token`` representing the authenticated user.
    ///
    /// An example JSON request body for authenticating a user:
    /// ```
    /// {
    ///    "email": "john@citizen.com",
    ///    "password": "a1b2c3d4"
    /// }
    /// ```
    func authenticate(_ req: Request) async throws -> Token {
        webApp.logger.debug("authenticate Entry")
        
        defer {
            webApp.logger.debug("authenticate Exit")
        }
        
        // Validate the request data.
        try UserAuthentication.validate(content: req)
        let authenticate = try req.content.decode(UserAuthentication.self)
        
        do {
            return try await authTokenService.password(username: authenticate.username, password: authenticate.password)
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
    
    /// The user sign-up request.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    /// - Returns: A ``OTPChallenge`` structure representing the new user sign-up.
    ///
    /// An example JSON request body for initiating a user sign-up:
    /// ```
    /// {
    ///    "name": "John Citizen",
    ///    "email": "john@citizen.com"
    /// }
    /// ```
    func signup(_ req: Request) async throws -> OTPChallenge {
        webApp.logger.debug("signup Entry")
        
        defer {
            webApp.logger.debug("signup Exit")
        }
        
        // Validate the request data.
        try UserSignUp.validate(content: req)
        let user = try req.content.decode(UserSignUp.self)
        
        do {
            let result = try await userService.generateOTP(token: try await token, email: user.email)
            
            // Calculate the cache expiry in seconds for the OTP transaction.
            let seconds = Int(result.expiry.timeIntervalSinceNow)
            req.logger.info("Caching OTP \(result.transactionId). Set to expire in \(seconds) seconds.")
            
            try await req.cache.set(result.transactionId, to: user, expiresIn: CacheExpirationTime.seconds(seconds))
            
            return result
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
    
    /// Validate the user sign-up request.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    /// - Returns: A ``Token`` representing the authenticated user.
    ///
    /// An example JSON request body for validating an one-time password challenge:
    /// ```
    /// {
    ///    "transactionId": "7705d361-f014-44c1-bae4-2877a0c962b6",
    ///    "otp": "123456"
    /// }
    /// ```
    func validate(_ req: Request) async throws -> Token {
        webApp.logger.debug("validate Entry")
        
        defer {
            webApp.logger.debug("validate Exit")
        }
        
        // Validate the request data.
        try OTPVerification.validate(content: req)
        let validation = try req.content.decode(OTPVerification.self)
        
        // Make sure the OTP transaction still exists in the cache.
        guard let user = try await req.cache.get(validation.transactionId, as: UserSignUp.self) else {
            req.logger.info("Cached \(validation.transactionId) OTP has expired.")
            throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Unable to parse one-time password identifer.")
        }
        
        do {
            let result = try await userService.verifyUser(token: try await token, transactionId: validation.transactionId, oneTimePassword: validation.otp, user: user)
            
            // Remove the transaction OTP from cache.
            req.logger.info("Removing \(validation.transactionId) OTP from cache.")
            try? await req.cache.delete(validation.transactionId)
            
            // Generate a JWT representing the userId with the signing secret being the client secret.
            let assertion = self.authTokenService.generateJWT(signingSecret: self.authTokenService.clientSecret, subject: result, issuer: webApp.addressDescription)
            
            return try await self.authTokenService.jwtBearer(assertion: assertion)
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
    
    /// A request to generate a WebAuthn challenge.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    /// - Returns: A ``FIDO2Challenge`` structure for the registration or sign-in attempt.
    ///
    /// An example JSON request body for obtaining a challenge for registration:
    /// ```
    /// {
    ///    "displayName": "John's iPhone",
    ///    "type": "attestation"
    /// }
    /// ```
    ///
    /// The `displayName` is ignored when a assertion challenge is requested.
    ///
    /// Requesting a challenge to complete a subsequent registration operation (attestation) requires the request to have an authorization request header.
    func challenge(_ req: Request) async throws -> Response {
        webApp.logger.debug("challenge Entry")
        
        defer {
            webApp.logger.debug("challenge Exit")
        }
        
        // Validate the request data.
        let challenge = try req.content.decode(ChallengeRequest.self)
        
        // Default displayName to nil for assertion requests.
        let displayName: String? = challenge.type == .assertion ? nil : challenge.displayName
        
        // Default to the service token.
        var token = try await token
        
        if let bearer = req.headers.bearerAuthorization {
            token = Token(accessToken: bearer.token)
        }
        
        req.logger.info("Request for \(challenge.type) challenge.")
        
        do {
            // Remove the reserved headers from the incoming request headers.
            let headers = req.headers.filter(({ !reservedHeaders.contains($0.name.lowercased()) }))
            
            let body = try await webAuthnService.generateChallenge(token: token, displayName: displayName, type: challenge.type,
                                                                   headers: headers.reduce(into: [String: String]()) { $0[$1.name] = $1.value })
            
            return Response(status: .ok, headers: HTTPHeaders([("Content-type", "application/json")]), body: .init(stringLiteral: body))
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
    
    /// A request to present an attestation object containing a public key to the server for attestation verification and storage.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    ///
    /// An example JSON request body for registering a FIDO2 device:
    /// ```
    /// {
    ///    "nickname": "John's iPhone",
    ///    "clientDataJSON": "eyUyBg8Li8GH...",
    ///    "attestationObject": "o2M884Yt0a3B7...",
    ///    "credentialId": "VGhpcyBpcyBh..."
    /// }
    func register(_ req: Request) async throws -> HTTPStatus {
        webApp.logger.debug("register Entry")
        
        defer {
            webApp.logger.debug("register Exit")
        }
        
        // Check if the bearer header is present, it not throw a 401.
        guard let bearer = req.headers.bearerAuthorization else {
            throw Abort(.unauthorized)
        }
        
        // Create the token.
        let token = Token(accessToken: bearer.token)
        
        // Validate the request data.
        try FIDO2Registration.validate(content: req)
        let registration = try req.content.decode(FIDO2Registration.self)
        
        do {
            // Remove the reserved headers from the incoming request headers.
            let headers = req.headers.filter(({ !reservedHeaders.contains($0.name.lowercased()) }))
            
            try await webAuthnService.createCredential(token: token, nickname: registration.nickname, clientDataJSON: registration.clientDataJSON, attestationObject: registration.attestationObject, credentialId: registration.credentialId, headers: headers.reduce(into: [String: String]()) { $0[$1.name] = $1.value })
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
        
        return HTTPStatus.created
    }
    
    /// A request to present the signed challenge to the server for verification.
    /// - Parameters:
    ///   - req: Represents an HTTP request.
    /// - Returns: A ``Token`` representing the authenticated user.
    ///
    /// An example JSON request body for verifing a FIDO2 device:
    /// ```
    /// {
    ///    "clientDataJSON": "eyUyBg8Li8GH...",
    ///    "authenticatorData": "o2M884Yt0a3B7...",
    ///    "credentialId": "VGhpcyBpcyBh...",
    ///    "signature": "OP84jBpcyB...",
    ///    "userHandle": "a1b2c3d4"
    /// }
    func signin(_ req: Request) async throws -> Response {
        webApp.logger.debug("signin Entry")
        
        defer {
            webApp.logger.debug("signin Exit")
        }
        
        // Validate the request data.
        try FIDO2Verification.validate(content: req)
        let verification = try req.content.decode(FIDO2Verification.self)
        
        do {
            let result = try await webAuthnService.verifyCredential(token: try await token, clientDataJSON: verification.clientDataJSON, authenticatorData: verification.authenticatorData, credentialId: verification.credentialId, signature: verification.signature, userHandle: verification.userHandle)
            
            // Default behaviour is to create a token from the response payload.
            if let response = try await createSigninTokenResponse(result) {
               return response
            }
            
            // For ISVA, use the AUTH_SESSION header to create cookie headers or EAI headers as the response.
            if self.platform == .isva {
                if self.authSession == .cookies {
                    return await createSigninCookieResponse(result)
                }
                else if self.authSession == .eai {
                    return try await createSigninEAIResponse(result)
                }
            }
            
            throw Abort(HTTPResponseStatus(statusCode: 400), reason: "The response from \(self.platform.rawValue) did not contain an OIDC token or an authenticated session cookie(s).  Please check your \(self.platform.rawValue) environment configuration.")
        }
        catch let error {
            req.logger.error(Logger.Message(stringLiteral: error.localizedDescription))
            throw error
        }
    }
}

// MARK: Helper Methods
extension DefaultRoute {
    /// Parse the assertion result from the FIDO2 endpoint and construct a `Response` with an OAuth token body.
    /// - Parameters:
    ///   - response: The `ClientResponse` from the FIDO service.
    /// - Returns: A ``Response`` otherwise `nil` representing the token data was not available.
    func createSigninTokenResponse(_ response: ClientResponse) async throws -> Response? {
        webApp.logger.debug("createSigninTokenResponse Entry")
        
        defer {
            webApp.logger.debug("createSigninTokenResponse Exit")
        }
        
        guard let body = response.body else {
            throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Unable to construct token from repsonse body data.")
        }
        
        let data = Data(buffer: body)
        
        switch self.platform {
        // For ISVA, the token response is based on the response including "access_token" in payload dervied from an ISVA mapping rule
        case .isva:
            guard let jsonData = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let attributes = jsonData["attributes"] as? [String: Any], let responseData = attributes["responseData"] as? [String: Any], let accessToken = responseData["access_token"] as? String else {
                
                webApp.logger.info("Unable to parse the ISVA assertion data from the FIDO2 assertion/result response.  Check the FIDO2 mediator Javascript.")
                return nil
            }

            let token = Token(accessToken: accessToken)
            let json = try JSONEncoder().encode(token)
            
            return Response(status: .ok, headers: HTTPHeaders([("Content-type", "application/json")]), body: .init(data: json))

        // For ISV, the JWT is created and validated, so we can just return the token.
        case .isv:
            guard let jsonData = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let assertion = jsonData["assertion"] as? String else {
                throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Unable to parse the ISV assertion data from the FIDO2 assertion/result response.")
            }
            
            let token = try await authTokenService.jwtBearer(assertion: assertion)
            let json = try JSONEncoder().encode(token)
            
            return Response(status: .ok, headers: HTTPHeaders([("Content-type", "application/json")]), body: .init(data: json))
        }
    }
    
    /// Parse the assertion result from the FIDO2 endpoint and construct a `Response` with the headers and body preserved.
    /// - Parameters:
    ///   - response: The `ClientResponse` from the FIDO service.
    /// - Returns: A ``Response``.
    func createSigninCookieResponse(_ response: ClientResponse) async -> Response {
        webApp.logger.debug("createSigninCookieResponse Entry")
        
        defer {
            webApp.logger.debug("createSigninCookieResponse Exit")
        }
        
        if let body = response.body {
            return Response(status: .ok, headers: response.headers, body: .init(data: Data(buffer: body)))
        }
        
        if let cookies = response.headers.setCookie {
            webApp.logger.debug("Cookie headers:\n\(cookies)")
        }
        
        return Response(status: .ok, headers: response.headers)
    }
    
    /// Parse the assertion result from the FIDO2 endpoint and construct a `Response` with the EAI specific headers.
    /// - Parameters:
    ///   - response: The `ClientResponse` from the FIDO service.
    /// - Returns: A ``Response``.
    func createSigninEAIResponse(_ response: ClientResponse) async throws -> Response {
        webApp.logger.debug("createSigninEAIResponse Entry")
        
        defer {
            webApp.logger.debug("createSigninEAIResponse Exit")
        }
        
        guard let body = response.body else {
            throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Unable to construct EAI data from repsonse body data.")
        }
        
        let data = Data(buffer: body)
        
        guard let jsonData = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let user = jsonData["user"] as? [String: Any], let username = user["name"] as? String, let attributes = jsonData["attributes"] as? [String: Any], let credentialData = attributes["credentialData"] as? [String: Any] else {
            throw Abort(HTTPResponseStatus(statusCode: 400), reason: "Unable to parse the ISVA assertion data from the FIDO2 assertion/result response.  Check the FIDO2 mediator Javascript.")
        }
        
        // Create the EAI headers
        var headers = HTTPHeaders()
        headers.add(name: "am-eai-user-id", value: username)
        headers.add(name: "am-eai-xattrs", value: credentialData.keys.joined(separator: ","))
        
        // Loop through the credentialData
        credentialData.forEach {
            let name = $0.key
            
            if let value = $0.value as? [String] {
                value.forEach {
                    headers.add(name: name, value: $0)
                }
            }
            
            if let value = $0.value as? String {
                headers.add(name: name, value: value)
            }
        }
        
        webApp.logger.debug("EAI headers:\n\(headers)")
        
        return Response(status: .noContent, headers: headers)
    }
    
    /// The ``Token`` for authorizing requests to back-end services.
    var token: Token {
        get async throws {
            webApp.logger.debug("token Entry")
            
            defer {
                webApp.logger.debug("token Exit")
            }
            
            // Get token from cache
            if let value = try await webApp.cache.get("token", as: Token.self) {
                webApp.logger.info("Cached token \(value.accessToken).")
                return value
            }
            
            // Obtain a new token.
            let value = try await self.apiTokenService.clientCredentials()
            
            // Add to cache but will expiry the token (in cache) 60 before it's actual expiry.
            try await webApp.cache.set("token", to: value, expiresIn: CacheExpirationTime.seconds(value.expiry - 60))
            webApp.logger.info("Caching token \(value.accessToken). Set to expire in \(value.expiry - 60) seconds.")
            return value
        }
    }
}
