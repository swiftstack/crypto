import Hex

extension SHA1.Hash {
    public var bigEndian: SHA1.Hash {
        return .init(
            a: a.bigEndian,
            b: b.bigEndian,
            c: c.bigEndian,
            d: d.bigEndian,
            e: e.bigEndian)
    }
}

extension Array where Element == UInt8 {
    public init(_ hash: SHA1.Hash) {
        var result = [UInt8](repeating: 0, count: 20)
        result.withUnsafeMutableBufferPointer { buffer in
            buffer.withMemoryRebound(to: UInt32.self) { buffer in
                let hash = hash.bigEndian
                buffer[0] = hash.a
                buffer[1] = hash.b
                buffer[2] = hash.c
                buffer[3] = hash.d
                buffer[4] = hash.e
            }
        }
        self = result
    }

    public func sha1() -> [UInt8] {
        var sha1 = SHA1()
        sha1.update(self)
        let hash = sha1.final()
        return [UInt8](hash)
    }
}

extension String {
    public init(_ hash: SHA1.Hash) {
        var hash = hash.bigEndian
        self = withUnsafeBytes(of: &hash) { buffer in
            return String(encodingToHex: buffer)
        }
    }
}
