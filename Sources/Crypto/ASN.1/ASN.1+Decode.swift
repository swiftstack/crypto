import Stream

extension ASN1 {
    public init(from stream: StreamReader) throws {
        let reader = Reader(from: stream)
        let identifier = try reader.readIdentifier()

        self.identifier = identifier
        switch identifier.isConstructed {
        case true:
            let length = try reader.readLength()
            self.content = try stream.withSubStream(limitedBy: length)
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
                self.content = .integer(try reader.read(Int.self))
            case .printableString, .utf8String:
                self.content = .string(try reader.read(String.self))
            default:
                self.content = .data(try reader.read([UInt8].self))
            }
        }
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

        func readIdentifier() throws -> Identifier {
            guard let identifier = Identifier(rawValue: try readRawTag()) else {
                throw Error.invalidIdentifier
            }
            return identifier
        }

        func readRawTag() throws -> Int {
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

        func readLength() throws -> Int {
            let length = try stream.read(UInt8.self)
            switch length & 0x80 {
            case 0: return Int(length)
            default:
                switch length & ~0x80 {
                case 1: return Int(try stream.read(UInt8.self))
                case 2: return Int(try stream.read(UInt16.self))
                case 4: return Int(try stream.read(UInt32.self))
                default: throw Error.invalidLength
                }
            }
        }

        func read(_ type: Int.Type) throws -> Int {
            var value = 0
            switch try readLength() {
            case 1: value = Int(try stream.read(UInt8.self))
            case 2: value = Int(try stream.read(UInt16.self))
            case 4: value = Int(try stream.read(UInt32.self))
            default: throw Error.invalidLength
            }
            return value
        }

        func read(_ type: [UInt8].Type) throws ->  [UInt8] {
            return try stream.read(count: try readLength())
        }

        func read(_ type: String.Type) throws -> String {
            return try stream.read(count: try readLength(), as: String.self)
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
