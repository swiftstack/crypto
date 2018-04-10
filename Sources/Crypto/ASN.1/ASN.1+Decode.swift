import Stream

extension ASN1 {
    public init(from stream: StreamReader) throws {
        let reader = Reader(from: stream)
        self = try reader.read(ASN1.self)
    }
}

extension ASN1.Identifier: RawRepresentable {
    public var rawValue: Int {
        let rawTag = tag.rawValue & (`class`.rawValue << 6)
        return isConstructed ? Int(rawTag & 0x20) : Int(rawTag)
    }

    public init?(rawValue raw: Int) {
        guard let `class` = Class(rawValue: UInt8((raw & 0xc0) >> 6)) else {
            return nil
        }
        guard let tag = Tag(rawValue: UInt8(raw & 0x1f)) else {
            return nil
        }
        self.isConstructed = raw & 0x20 == 0x20
        self.class = `class`
        self.tag = tag
    }
}

extension ASN1 {
    public class Reader {
        let stream: StreamReader

        public init(from stream: StreamReader) {
            self.stream = stream
        }

        public enum Error: Swift.Error {
            case invalidLength
            case invalidIdentifier
        }

        func read(_ asn1: ASN1.Type) throws -> ASN1 {
            let identifier = try read(Identifier.self)

            let content: ASN1.Content

            switch identifier.isConstructed {
            case true:
                content = try stream.withSubStream(sizedBy: Length.self)
                { stream in
                    var children = [ASN1]()
                    while !stream.isEmpty {
                        children.append(try ASN1(from: stream))
                    }
                    return .sequence(children)
                }
            case false:
                switch identifier.tag {
                case .enumerated:
                    content = .integer(try read(Int.self))
                case .printableString, .utf8String:
                    content = .string(try read(String.self))
                default:
                    content = .data(try read([UInt8].self))
                }
            }

            return ASN1(identifier: identifier, content: content)
        }

        func read(_ identifier: Identifier.Type) throws -> Identifier {
            let mask = try readIdentifierMask()
            guard let identifier = Identifier(rawValue: mask) else {
                throw Error.invalidIdentifier
            }
            return identifier
        }

        func readIdentifierMask() throws -> Int {
            let tag = Int(try stream.read(UInt8.self))
            guard tag & 0x1F == 0x1F else {
                return tag
            }
            return try stream.read(while: { $0 & 0x80 == 0x80 }) { buffer in
                var tag = 0
                for byte in buffer {
                    tag <<= 8
                    tag |= Int(byte & 0x7F)
                }
                return tag
            }
        }

        func read(_ type: Int.Type) throws -> Int {
            var value = 0
            switch try Length(from: stream).value {
            case 1: value = Int(try stream.read(UInt8.self))
            case 2: value = Int(try stream.read(UInt16.self))
            case 4: value = Int(try stream.read(UInt32.self))
            default: throw Error.invalidLength
            }
            return value
        }

        func read(_ type: [UInt8].Type) throws ->  [UInt8] {
            let length = try Length(from: stream)
            return try stream.read(count: length.value)
        }

        func read(_ type: String.Type) throws -> String {
            let length = try Length(from: stream)
            return try stream.read(count: length.value, as: String.self)
        }
    }
}

extension String {
    public init(oid bytes: [UInt8]) {
        guard !bytes.isEmpty else {
            self = ""
            return
        }

        var oid: String = "\(bytes[0] / 40).\(bytes[0] % 40)"

        var next = 0
        for byte in bytes[1...] {
            next = (next << 7) | (Int(byte) & 0x7F)
            if (byte & 0x80) == 0 {
                oid.append(".\(next)")
                next = 0
            }
        }

        self = oid
    }
}
