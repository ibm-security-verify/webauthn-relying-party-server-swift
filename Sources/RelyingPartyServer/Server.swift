//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor
import NIOSSL

/// Main entry point into the Vapor application.
@main
struct RelyingPartyServer {
    public static func main() async throws {
        var env = try Environment.detect()
        try LoggingSystem.bootstrap(from: &env)

        let webApp = Application(env)
        defer {
            webApp.shutdown()
        }
        
        // MARK: Configure Sessions
        webApp.sessions.use(.memory)
        webApp.middleware.use(SessionsMiddleware(session: MemorySessions(storage: .init())))
        
        // MARK: Configure Cache
        webApp.caches.use(.memory)
        
        // MARK: Configure Routes
        try webApp.register(collection: WellKnownRoute())
        try webApp.register(collection: DefaultRoute(webApp))
        
        // MARK: Configure HTTP Client
        webApp.http.client.configuration.timeout = HTTPClient.Configuration.Timeout(connect: .seconds(30))
        
        // Configure the proxy if settings provided.
        if let proxy = Environment.get("HTTP_PROXY") {
            let pattern = #/(?:\/\/(?:(?<username>[^:]+)?:(?<password>[^:]+)@)?(?<host>[^:]+):(?<port>[0-9]+))/#
            
            if let match = proxy.firstMatch(of: pattern), let port = Int(match.port) {
                var message = "Server proxy configured on \(match.host):\(match.port)"
                var authorization: HTTPClient.Authorization? = nil
                
                if let username = match.username, let password = match.password {
                    message += " with authentication"
                    authorization = HTTPClient.Authorization.basic(username: String(username), password: String(password))
                }
                
                webApp.logger.notice(Logger.Message(stringLiteral: message))
                webApp.http.client.configuration.proxy = .server(host: String(match.host), port: port, authorization: authorization)
            }
        }
        
        // Add root certificate authority if provided.
        if let value = Environment.get("ROOT_CA"), let data = Data(base64Encoded: value), let certificate = String(data: data, encoding: .utf8) {
            let bytes = [UInt8](certificate.utf8)
            
            var tlsConfiguration = TLSConfiguration.makeClientConfiguration()
            tlsConfiguration.additionalTrustRoots.append(.certificates([
                try NIOSSLCertificate(bytes: bytes, format: NIOSSLSerializationFormats.pem)
            ]))
        
            webApp.logger.notice("Adding root certificate authority for client requests")
            webApp.http.client.configuration.tlsConfiguration = tlsConfiguration
        }
            
        try webApp.run()
    }
}
