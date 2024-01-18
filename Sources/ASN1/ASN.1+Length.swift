import Stream

extension ASN1 {
    struct Length {
        let value: Int

        init(_  value: Int) {
            self.value = value
        }

        public enum Error: Swift.Error {
            case invalidLength
        }

        static func decode(from stream: StreamReader) async throws -> Self {
            let length = try await stream.read(UInt8.self)
            switch length & 0x80 {
            case 0: return .init(Int(length))
            default:
                switch length & ~0x80 {
                case 1: return .init(Int(try await stream.read(UInt8.self)))
                case 2: return .init(Int(try await stream.read(UInt16.self)))
                case 4: return .init(Int(try await stream.read(UInt32.self)))
                default: throw Error.invalidLength
                }
            }
        }

        func encode(to stream: StreamWriter) async throws {
            switch value {
            case 0...0x7F:
                try await stream.write(UInt8(value))
            case 0x80...0xFF:
                try await stream.write(UInt8(0x81))
                try await stream.write(UInt8(value))
            case 0x01_00...0xFF_FF:
                try await stream.write(UInt8(0x82))
                try await stream.write(UInt16(value))
            case 0x0001_0000...0xFFFF_FFFF:
                try await stream.write(UInt8(0x84))
                try await stream.write(UInt32(value))
            default:
                throw Error.invalidLength
            }
        }
    }
}

extension StreamReader {
    func withSubStreamReader<T>(
        sizedBy type: ASN1.Length.Type,
        body: (SubStreamReader) async throws -> T
    ) async throws -> T {
        let length = try await ASN1.Length.decode(from: self)
        return try await withSubStreamReader(
            limitedBy: length.value,
            body: body)
    }
}

extension StreamWriter {
    func withSubStreamWriter(
        sizedBy type: ASN1.Length.Type,
        body: (SubStreamWriter) async throws -> Void
    ) async throws {
        let output = OutputByteStream()
        try await body(output)
        let length = ASN1.Length(output.bytes.count)
        try await length.encode(to: self)
        try await write(output.bytes)
    }
}
