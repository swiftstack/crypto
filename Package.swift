// swift-tools-version:5.2
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(
            name: "SHA1",
            targets: ["SHA1"]),
        .library(
            name: "UUID",
            targets: ["UUID"]),
        .library(
            name: "ASN1",
            targets: ["ASN1"]),
        .library(
            name: "Crypto",
            targets: ["Crypto"])
    ],
    dependencies: [
        .package(name: "Stream"),
        .package(name: "Radix"),
        .package(name: "Time"),
        .package(name: "Test")
    ],
    targets: [
        .target(name: "UInt24"),
        .target(
            name: "SHA1",
            dependencies: [
                .product(name: "Hex", package: "Radix")]),
        .target(
            name: "UUID",
            dependencies: [
                .product(name: "Hex", package: "Radix"), "SHA1"]),
        .target(
            name: "ASN1",
            dependencies: [
                "UInt24", "Stream", .product(name: "Hex", package: "Radix")]),
        .target(
            name: "X509",
            dependencies: ["ASN1", "Stream", "Time"]),
        .target(
            name: "Crypto",
            dependencies: ["SHA1", "UUID", "ASN1", "X509"]),
        .testTarget(
            name: "SHA1Tests",
            dependencies: ["Test", "SHA1"]),
        .testTarget(
            name: "UUIDTests",
            dependencies: ["Test", "UUID"]),
        .testTarget(
            name: "ASN1Tests",
            dependencies: ["Test", "ASN1"]),
        .testTarget(
            name: "X509Tests",
            dependencies: ["Test", "X509"]),
        .testTarget(
            name: "UInt24Tests",
            dependencies: ["Test", "UInt24"]),
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
            : .package(name: name, url: source.url(for: name), .branch("fiber"))
    }
}
