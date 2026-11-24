// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "httpsig",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "HTTPSig", targets: ["HTTPSig"]),
        .library(name: "HTTPSigURLSession", targets: ["HTTPSigURLSession"]),
        .library(name: "HTTPSigAlamofire", targets: ["HTTPSigAlamofire"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMajor(from: "5.9.0")),
    ],
    targets: [
        .target(
            name: "HTTPSig",
            path: "swift/Sources/HTTPSig"
        ),
        .target(
            name: "HTTPSigURLSession",
            dependencies: ["HTTPSig"],
            path: "swift/Sources/HTTPSigURLSession"
        ),
        .target(
            name: "HTTPSigAlamofire",
            dependencies: ["HTTPSigURLSession", "Alamofire"],
            path: "swift/Sources/HTTPSigAlamofire"
        ),
        .testTarget(
            name: "HTTPSigTests",
            dependencies: ["HTTPSig"],
            path: "swift/Tests/HTTPSigTests"
        ),
        .testTarget(
            name: "HTTPSigURLSessionTests",
            dependencies: ["HTTPSigURLSession", "HTTPSig"],
            path: "swift/Tests/HTTPSigURLSessionTests"
        ),
        .testTarget(
            name: "HTTPSigAlamofireTests",
            dependencies: ["HTTPSigAlamofire", "HTTPSig"],
            path: "swift/Tests/HTTPSigAlamofireTests"
        ),
    ]
)
