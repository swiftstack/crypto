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

        static func decode<T: StreamReader>(from stream: T) async throws -> Self {
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

        func encode<T: StreamWriter>(to stream: T) async throws {
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

extension ASN1.Length: LengthHeader {
    init(length: Int) {
        self.init(length)
    }

    var length: Int { value }

    init<T: StreamReader>(from stream: T) async throws {
        self = try await ASN1.Length.decode(from: stream)
    }

    func write<T: StreamWriter>(to stream: T) async throws {
        try await encode(to: stream)
    }
}
