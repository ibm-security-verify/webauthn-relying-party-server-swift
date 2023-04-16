//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// Ensures the response header content type is `application/json` for requests to the `.well-known` endpoint.
struct WellKnownMiddleware: Middleware {
    func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {
        return next.respond(to: request).map { response in
            response.headers.contentType = .json
            return response
        }
    }
}
