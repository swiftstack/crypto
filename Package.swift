// swift-tools-version:5.4
import PackageDescription

let package = Package(
    name: "Crypto",
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
                .product(name: "Hex", package: "Radix")],
            swiftSettings: [
                .unsafeFlags(["-Xfrontend", "-enable-experimental-concurrency"])
            ]),
        .target(
            name: "UUID",
            dependencies: [
                .product(name: "Hex", package: "Radix"), "SHA1"],
            swiftSettings: [
                .unsafeFlags(["-Xfrontend", "-enable-experimental-concurrency"])
            ]),
        .target(
            name: "ASN1",
            dependencies: [
                "UInt24", "Stream", .product(name: "Hex", package: "Radix")],
            swiftSettings: [
                .unsafeFlags(["-Xfrontend", "-enable-experimental-concurrency"])
            ]),
        .target(
            name: "X509",
            dependencies: ["ASN1", "Stream", "Time"],
            swiftSettings: [
                .unsafeFlags(["-Xfrontend", "-enable-experimental-concurrency"])
            ]),
        .target(
            name: "Crypto",
            dependencies: ["SHA1", "UUID", "ASN1", "X509"],
            swiftSettings: [
                .unsafeFlags(["-Xfrontend", "-enable-experimental-concurrency"])
            ]),
    ]
)

// MARK: - tests

testTarget("ASN1") { test in
    test("ASN1")
    test("Decode")
    test("Description")
    test("Encode")
    test("Length")
}

testTarget("SHA1") { test in
    test("SHA1")
}

testTarget("UInt24") { test in
    test("UInt24")
}

testTarget("UUID") { test in
    test("UUID")
}

testTarget("X509") { test in
    test("CertificateDecode")
    test("ExtensionDecode")
    test("OCSPDecode")
}

func testTarget(_ target: String, task: ((String) -> Void) -> Void) {
    task { test in addTest(target: target, name: test) }
}

func addTest(target: String, name: String) {
    package.targets.append(
        .executableTarget(
            name: "Tests/\(target)/\(name)",
            dependencies: [.init(stringLiteral: target), "Test"],
            path: "Tests/\(target)/\(name)",
            swiftSettings: [
                .unsafeFlags(["-Xfrontend", "-enable-experimental-concurrency"])
            ]))
}

// MARK: - custom package source

#if canImport(ObjectiveC)
import Darwin.C
#else
import Glibc
#endif

extension Package.Dependency {
    enum Source: String {
        case local, remote, github

        static var `default`: Self { .local }

        var baseUrl: String {
            switch self {
            case .local: return "../"
            case .remote: return "https://swiftstack.io/"
            case .github: return "https://github.com/swift-stack/"
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
            : .package(name: name, url: source.url(for: name), .branch("dev"))
    }
}
