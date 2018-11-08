import Hex

private func bigEndian(_ hash: SHA1.Hash) -> SHA1.Hash {
    return (hash.0.bigEndian, 
            hash.1.bigEndian, 
            hash.2.bigEndian,
            hash.3.bigEndian,
            hash.4.bigEndian)
}

extension Array where Element == UInt8 {
    public init(_ hash: SHA1.Hash) {
        var result = [UInt8](repeating: 0, count: 20)
        result.withUnsafeMutableBufferPointer { buffer in
            buffer.withMemoryRebound(to: UInt32.self) { buffer in
                let hash = bigEndian(hash)
                buffer[0] = hash.0
                buffer[1] = hash.1
                buffer[2] = hash.2
                buffer[3] = hash.3
                buffer[4] = hash.4
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
        var hash = bigEndian(hash)
        self = withUnsafeBytes(of: &hash) { buffer in
            return String(encodingToHex: buffer)
        }
    }
}
