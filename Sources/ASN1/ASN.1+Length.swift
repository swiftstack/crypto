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

        init(from stream: StreamReader) throws {
            let length = try stream.read(UInt8.self)
            switch length & 0x80 {
            case 0: self.value = Int(length)
            default:
                switch length & ~0x80 {
                case 1: self.value = Int(try stream.read(UInt8.self))
                case 2: self.value = Int(try stream.read(UInt16.self))
                case 4: self.value = Int(try stream.read(UInt32.self))
                default: throw Error.invalidLength
                }
            }
        }

        func encode(to stream: StreamWriter) throws {
            switch value {
            case 0...0x7F:
                try stream.write(UInt8(value))
            case 0x80...0xFF:
                try stream.write(UInt8(0x81))
                try stream.write(UInt8(value))
            case 0x01_00...0xFF_FF:
                try stream.write(UInt8(0x82))
                try stream.write(UInt16(value))
            case 0x0001_0000...0xFFFF_FFFF:
                try stream.write(UInt8(0x84))
                try stream.write(UInt32(value))
            default:
                throw Error.invalidLength
            }
        }
    }
}

extension StreamReader {
    func withSubStream<T>(
        sizedBy type: ASN1.Length.Type,
        body: (SubStreamReader) throws -> T) throws -> T
    {
        let length = try ASN1.Length(from: self)
        return try withSubStream(limitedBy: length.value, body: body)
    }
}

extension StreamWriter {
    func withSubStream(
        sizedBy type: ASN1.Length.Type,
        body: (SubStreamWriter) throws -> Void) throws
    {
        let output = OutputByteStream()
        try body(output)
        let length = ASN1.Length(output.bytes.count)
        try length.encode(to: self)
        try write(output.bytes)
    }
}
