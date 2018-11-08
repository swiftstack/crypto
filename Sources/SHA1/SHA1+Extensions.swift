import Hex

extension Array where Element == UInt8 {
    public init(_ hash: SHA1.Hash) {
        var result = [UInt32]()
        result.reserveCapacity(5)
        result.append(hash.0.bigEndian)
        result.append(hash.1.bigEndian)
        result.append(hash.2.bigEndian)
        result.append(hash.3.bigEndian)
        result.append(hash.4.bigEndian)

        self = [UInt8](UnsafeRawBufferPointer(start: result, count: 20))
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
        self = String(encodingToHex:[UInt8](hash))
    }
}
