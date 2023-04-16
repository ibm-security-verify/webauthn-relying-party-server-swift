//
// Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
//

import Vapor

extension Application {
    /// The absolute string for the HTTP server.
    var addressDescription: String {
        let configuration = http.server.configuration
        let scheme = configuration.tlsConfiguration == nil ? "http" : "https"
        let addressDescription: String
        
        switch configuration.address {
        case .hostname(let hostname, let port):
            addressDescription = "\(scheme)://\(hostname ?? configuration.hostname):\(port ?? configuration.port)"
        case .unixDomainSocket(let socketPath):
            addressDescription = "\(scheme)+unix: \(socketPath)"
        }
        
        return addressDescription
    }
}
