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
