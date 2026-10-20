// swift-tools-version:5.9
// openback-app-auth-ios: the Swift client of OpenBack's App authenticator (users-service user pools).
// Library product and module: OpenBackAppAuth (Swift module names cannot contain hyphens).
import PackageDescription

let package = Package(
    name: "openback-app-auth-ios",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v8),
    ],
    products: [
        .library(name: "OpenBackAppAuth", targets: ["OpenBackAppAuth"]),
    ],
    targets: [
        .target(
            name: "OpenBackAppAuth",
            path: "Sources/OpenBackAppAuth"
        ),
        .testTarget(
            name: "OpenBackAppAuthTests",
            dependencies: ["OpenBackAppAuth"],
            path: "Tests/OpenBackAppAuthTests"
        ),
    ]
)
