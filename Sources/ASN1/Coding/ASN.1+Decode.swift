import UInt24
import Stream

extension ASN1: StreamReadable {
    public init<T: StreamReader>(from stream: T) async throws {
        let reader = Reader(from: stream)
        self = try await reader.read(ASN1.self)
    }
}

extension ASN1.Identifier: StreamReadable {
    public init<T: StreamReader>(from stream: T) async throws {
        let reader = ASN1.Reader(from: stream)
        self = try await reader.read(ASN1.Identifier.self)
    }
}

extension ASN1 {
    public class Reader<T: StreamReader> {
        let stream: T

        public init(from stream: T) {
            self.stream = stream
        }

        public enum Error: Swift.Error {
            case invalidLength
            case invalidIdentifier
            case invalidBoolean
        }

        func read(_ asn1: ASN1.Type) async throws -> ASN1 {
            let identifier = try await read(Identifier.self)

            let content: ASN1.Content

            switch identifier.isConstructed {
            case true:
                content = try await stream.withSubStreamReader(
                    sizedBy: Length.self
                ) { stream in
                    var children = [ASN1]()
                    while try await stream.cache(count: 1) {
                        try await children.append(ASN1(from: stream))
                    }
                    return .sequence(children)
                }
            case false:
                switch identifier.tag {
                case .boolean:
                    content = .boolean(try await read(Bool.self))
                case .integer, .enumerated:
                    content = .integer(try await read(Integer.self))
                case .printableString, .utf8String:
                    content = .string(try await read(String.self))
                case .objectIdentifier:
                    content = .objectIdentifier(
                        try await read(ObjectIdentifier.self))
                default:
                    content = .data(try await read([UInt8].self))
                }
            }

            return ASN1(identifier: identifier, content: content)
        }

        func read(_ identifier: Identifier.Type) async throws -> Identifier {
            let mask = try await readIdentifierMask()

            let rawClass = UInt8((mask & 0xc0) >> 6)
            guard let `class` = Identifier.Class(rawValue: rawClass) else {
                throw Error.invalidIdentifier
            }
            let rawTag = UInt8(mask & 0x1f)
            guard let tag = Identifier.Tag(rawValue: rawTag) else {
                throw Error.invalidIdentifier
            }
            return Identifier(
                isConstructed: mask & 0x20 == 0x20,
                class: `class`,
                tag: tag)
        }

        func readIdentifierMask() async throws -> Int {
            let tag = Int(try await stream.read(UInt8.self))
            guard tag & 0x1F == 0x1F else {
                return tag
            }
            return try await stream.read(
                while: { $0 & 0x80 == 0x80 }
            ) { buffer in
                var tag = 0
                for byte in buffer {
                    tag <<= 8
                    tag |= Int(byte & 0x7F)
                }
                return tag
            }
        }

        func read(_ type: Bool.Type) async throws -> Bool {
            let length = try await Length(from: stream)
            guard length.value == 1 else {
                throw Error.invalidBoolean
            }
            return try await stream.read(UInt8.self) > 0
        }

        func read(_ type: Integer.Type) async throws -> Integer {
            let length = try await Length(from: stream)
            switch length.value {
            case 1: return .sane(Int(try await stream.read(Int8.self)))
            case 2: return .sane(Int(try await stream.read(Int16.self)))
            case 3: return .sane(Int(try await stream.read(UInt24.self)))
            case 4: return .sane(Int(try await stream.read(Int32.self)))
            case 8: return .sane(Int(try await stream.read(Int64.self)))
            default: return .insane(try await stream.read(count: length.value))
            }
        }

        func read(_ type: [UInt8].Type) async throws -> [UInt8] {
            let length = try await Length(from: stream)
            return try await stream.read(count: length.value)
        }

        func read(_ type: String.Type) async throws -> String {
            let length = try await Length(from: stream)
            return try await stream.read(count: length.value, as: String.self)
        }

        func read(
            _ type: ObjectIdentifier.Type
        ) async throws -> ObjectIdentifier {
            let bytes = try await read([UInt8].self)
            return .init(rawValue: bytes)
        }
    }
}
