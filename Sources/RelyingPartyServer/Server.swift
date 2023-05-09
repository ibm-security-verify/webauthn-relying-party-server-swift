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
        if let proxy = Environment.get("PROXY_HOST"), let proxyHost = URL(string: proxy), let port = Environment.get("PROXY_PORT"), let proxyPort = Int(port) {
            webApp.logger.notice("Server proxy configured on \(proxyHost.absoluteString):\(proxyPort)")
            webApp.http.client.configuration.proxy = .server(host: proxyHost.absoluteString, port: proxyPort)
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
