// swift-tools-version:6.4
import PackageDescription

let package = Package(
    name: "Crypto",
    platforms: [
        .iOS(.v26),
        .tvOS(.v26),
        .macOS(.v26),
        .watchOS(.v26),
        .visionOS(.v26),
    ],
    products: [
        .library(
            name: "SHA1",
            targets: ["SHA1"]),
        .library(
            name: "X509",
            targets: ["X509"]),
        .library(
            name: "UUID",
            targets: ["UUID"]),
        .library(
            name: "ASN1",
            targets: ["ASN1"]),
        .library(
            name: "Crypto",
            targets: ["Crypto"]),
    ],
    dependencies: [
        .package(name: "Stream"),
        .package(name: "Radix"),
    ],
    targets: [
        .target(
            name: "UInt24"
        ),
        .target(
            name: "SHA1",
            dependencies: [
                .product(name: "Hex", package: "Radix"),
            ],
            swiftSettings: [
                .treatWarning("EmbeddedRestrictions", as: .error)
            ]),
        .target(
            name: "UUID",
            dependencies: [
                .target(name: "SHA1"),
                .product(name: "Hex", package: "Radix"),
            ],
            swiftSettings: [
                .treatWarning("EmbeddedRestrictions", as: .error)
            ]),
        .target(
            name: "ASN1",
            dependencies: [
                .target(name: "UInt24"),
                .product(name: "Stream", package: "stream"),
                .product(name: "Hex", package: "Radix"),
            ],
            swiftSettings: [
                .treatWarning("EmbeddedRestrictions", as: .error)
            ]),
        .target(
            name: "X509",
            dependencies: [
                .target(name: "UInt24"),
                .target(name: "ASN1"),
                .product(name: "Stream", package: "stream"),
            ],
            swiftSettings: [
                .treatWarning("EmbeddedRestrictions", as: .error)
            ]),
        .target(
            name: "Crypto",
            dependencies: [
                .target(name: "SHA1"),
                .target(name: "UUID"),
                .target(name: "ASN1"),
                .target(name: "X509"),
            ],
            swiftSettings: [
                .treatWarning("EmbeddedRestrictions", as: .error)
            ]),
        .testTarget(
            name: "Tests",
            dependencies: [
                .target(name: "ASN1"),
                .target(name: "SHA1"),
                .target(name: "UInt24"),
                .target(name: "UUID"),
                .target(name: "X509"),
            ]),
    ]
)

// MARK: - custom package source

#if canImport(ObjectiveC)
import Darwin.C
#else
import Glibc
#endif

extension Package.Dependency {
    enum Source: String {
        case local, remote, github

        static var `default`: Self { .github }

        var baseUrl: String {
            switch self {
            case .local: return "../"
            case .remote: return "https://swiftstack.io/"
            case .github: return "https://github.com/swiftstack/"
            }
        }

        func url(for name: String) -> String {
            return self == .local
                ? baseUrl + name.lowercased()
                : baseUrl + name.lowercased() + ".git"
        }
    }

    static func package(name: String) -> Package.Dependency {
        guard let pointer = getenv("SWIFTSTACK") else {
            return .package(name: name, source: .default)
        }
        guard let source = Source(rawValue: String(cString: pointer)) else {
            fatalError("Invalid source. Use local, remote or github")
        }
        return .package(name: name, source: source)
    }

    static func package(name: String, source: Source) -> Package.Dependency {
        return source == .local
            ? .package(name: name, path: source.url(for: name))
            : .package(url: source.url(for: name), branch: "dev")
    }
}
