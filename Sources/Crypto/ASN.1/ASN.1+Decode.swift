import Stream

extension ASN1 {
    public init(from stream: StreamReader) throws {
        let reader = Reader(from: stream)
        self = try reader.read(ASN1.self)
    }
}

extension ASN1.Identifier {
    public init(from stream: StreamReader) throws {
        let reader = ASN1.Reader(from: stream)
        self = try reader.read(ASN1.Identifier.self)
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
            case invalidBoolean
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
                case .boolean:
                    content = .boolean(try read(Bool.self))
                case .integer, .enumerated:
                    content = .integer(try read(Integer.self))
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

        func read(_ type: Bool.Type) throws ->  Bool {
            let length = try Length(from: stream)
            guard length.value == 1 else {
                throw Error.invalidBoolean
            }
            return try stream.read(UInt8.self) > 0
        }

        func read(_ type: Integer.Type) throws -> Integer {
            let length = try Length(from: stream)
            switch length.value {
            case 1: return .sane(Int(try stream.read(Int8.self)))
            case 2: return .sane(Int(try stream.read(Int16.self)))
            case 3: return .sane(Int(try stream.read(UInt24.self)))
            case 4: return .sane(Int(try stream.read(Int32.self)))
            case 8: return .sane(Int(try stream.read(Int64.self)))
            default: return .insane(try stream.read(count: length.value))
            }
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
