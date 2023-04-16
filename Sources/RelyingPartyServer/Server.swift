//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// Main entry point into the Vapor application.
@main
struct RelyingPartyServer {
    public static func main() async throws {
        var env = try Environment.detect()
        try LoggingSystem.bootstrap(from: &env)

        let webapp = Application(env)
        defer {
            webapp.shutdown()
        }
        
        // MARK: Configure Sessions
        webapp.sessions.use(.memory)
        webapp.middleware.use(SessionsMiddleware(session: MemorySessions(storage: .init())))
        
        // MARK: Configure Cache
        webapp.caches.use(.memory)
        
        // MARK: Configure Routes
        try webapp.register(collection: WellKnownRoute())
        try webapp.register(collection: DefaultRoute(webapp))
        
        // MARK: Configure HTTP Client
        webapp.http.client.configuration.timeout = HTTPClient.Configuration.Timeout(connect: .seconds(30))
        
        try webapp.run()
    }
}
