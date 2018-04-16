// swift-tools-version:4.2
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto"])
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-stack/stream.git",
            .branch("master")),
        .package(
            url: "https://github.com/swift-stack/test.git",
            .branch("master"))
    ],
    targets: [
        .target(name: "Crypto", dependencies: ["Stream"]),
        .testTarget(name: "CryptoTests", dependencies: ["Crypto", "Test"]),
        .testTarget(name: "ASN1Tests", dependencies: ["Crypto", "Test"]),
        .testTarget(name: "UInt24Tests", dependencies: ["Test"])
    ]
)
