// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto"])
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-stack/test.git",
            from: "0.4.0"
        )
    ],
    targets: [
        .target(name: "Crypto"),
        .testTarget(
            name: "CryptoTests",
            dependencies: ["Crypto", "Test"]
        )
    ]
)
