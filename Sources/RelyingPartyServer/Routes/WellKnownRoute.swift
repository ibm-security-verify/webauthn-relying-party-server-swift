//
// Copyright contributors to the IBM Verify WebAuthn Relying Party Server for Swift
//

import Vapor

/// An enum of supported well-known endpoints.
private enum WellknownFiles: String {
    /// The AASA contains a JSON object with a list of apps and the URL paths on the domain that should be included or excluded as Universal Links or associated domains.
    ///
    /// For more information, see [Allowing apps and websites to link to your content](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
    case aasa = "apple-app-site-association"
    
    /// The assetlinks.json file contains information to enable an app or website to make public verifable statements about other apps or websites.
    ///
    /// For more information, see [Enable automatic sign-in across apps and websites](https://developers.google.com/identity/smartlock-passwords/android/associate-apps-and-sites)
    case assetlinks = "assetlinks.json"
}

/// The route controller for the `.well-known` endpoint.
struct WellKnownRoute: RouteCollection {
    private let appleAppSiteAssociation, assetLinks: String
    
    /// Initializes the well known route.
    init() throws {
        guard let appleAppSiteAssociation = Environment.get("APPLE_APP_SITE_ASSOC") else {
            fatalError("The JSON to construct the apple-app-site-association content is not set or invalid.")
        }
        
        guard let assetLinks = Environment.get("GOOGLE_ASSET_LINKS") else {
            fatalError("The JSON to construct the assetlinks.json content is not set or invalid.")
        }

        // Set the apple-app-site-association and assetlink content.
        self.appleAppSiteAssociation = appleAppSiteAssociation
        self.assetLinks = assetLinks
    }
    
    func boot(routes: Vapor.RoutesBuilder) throws {
        let route = routes.grouped(WellKnownMiddleware())
        route.get(".well-known", ":filename") { req -> String in
            // Ensure the parameter is provided and expected.
            if req.parameters.get("filename") == WellknownFiles.aasa.rawValue {
                // Return the content of the file, the WellKnownMiddleware will include the 'application/json' header.
                return self.appleAppSiteAssociation
            }
            
            if req.parameters.get("filename") == WellknownFiles.assetlinks.rawValue {
                // Return the content of the file, the WellKnownMiddleware will include the 'application/json' header.
                return self.assetLinks
            }
            
            throw Abort(.notFound)
        }
    }
}
