import UInt24
import Stream

public protocol StreamEncodable {
    func encode(to stream: StreamWriter) async throws
}

extension StreamEncodable {
    public func encode() async throws -> [UInt8] {
        let stream = OutputByteStream()
        try await encode(to: stream)
        return stream.bytes
    }
}

extension ASN1: StreamEncodable {
    public func encode(to stream: StreamWriter) async throws {
        let writer = Writer(to: stream)
        try await writer.write(self)
    }
}

extension ASN1.Identifier: StreamEncodable {
    public func encode(to stream: StreamWriter) async throws {
        var rawTag = tag.rawValue | (`class`.rawValue << 6)
        if isConstructed {
            rawTag |= 0x20
        }
        try await stream.write(UInt8(rawTag))
    }
}

extension ASN1 {
    public class Writer {
        let stream: StreamWriter

        public init(to stream: StreamWriter) {
            self.stream = stream
        }

        public enum Error: Swift.Error {
            case invalidLength
            case invalidIdentifier
        }

        func write(_ asn1: ASN1) async throws {
            try await asn1.identifier.encode(to: stream)

            switch asn1.content {
            case .boolean(let value) where
                asn1.identifier.tag == .boolean:
                try await write(value)
            case .integer(let value) where
                asn1.identifier.tag == .integer ||
                asn1.identifier.tag == .enumerated:
                 try await write(value)
            case .string(let value) where
                    asn1.identifier.tag == .printableString ||
                    asn1.identifier.tag == .utf8String:
                try await write(value)
            case .data(let value) where
                asn1.identifier.tag == .objectIdentifier ||
                asn1.identifier.tag == .octetString:
                try await write(value)
            case .sequence(let value) where asn1.identifier.isConstructed:
                try await write(value)
            default:
                throw Error.invalidIdentifier
            }
        }

        func write(_ values: [ASN1]) async throws {
            try await stream.withSubStreamWriter(sizedBy: Length.self) { stream in
                for value in values {
                    try await value.encode(to: stream)
                }
            }
        }

        func write(_ value: Bool) async throws {
            try await stream.write(UInt8(1))
            try await stream.write(value ? UInt8(0xFF) : UInt8(0x0))
        }

        func write(_ value: Integer) async throws {
            switch value {
            case .sane(let value):
                switch value {
                case 0...0xFF:
                    try await stream.write(UInt8(1))
                    try await stream.write(UInt8(value))
                case 0x01_00...0xFF_FF:
                    try await stream.write(UInt8(2))
                    try await stream.write(UInt16(value))
                case 0x0001_0000...0x00FF_FFFF:
                    try await stream.write(UInt8(3))
                    try await stream.write(UInt24(value))
                case 0x0100_0000...0xFFFF_FFFF:
                    try await stream.write(UInt8(4))
                    try await stream.write(UInt32(value))
                default:
                    try await stream.write(UInt8(8))
                    try await stream.write(UInt64(value))
                }
            case .insane(let bytes):
                let length = Length(bytes.count)
                try await length.encode(to: stream)
                try await stream.write(bytes)
            }
        }

        func write(_ bytes: [UInt8]) async throws {
            let length = Length(bytes.count)
            try await length.encode(to: stream)
            try await stream.write(bytes)
        }

        func write(_ string: String) async throws {
            try await write([UInt8](string.utf8))
        }
    }
}
