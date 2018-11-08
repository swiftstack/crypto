import Hex

extension UUID {
    public var uuidString: String {
        var result = ""
        result.reserveCapacity(36)
        var uuid = self
        withUnsafeBytes(of: &uuid) { buffer in
            result += String(encodingToHex: .init(rebasing: buffer[..<4]))
            result += "-"
            result += String(encodingToHex: .init(rebasing: buffer[4..<6]))
            result += "-"
            result += String(encodingToHex: .init(rebasing: buffer[6..<8]))
            result += "-"
            result += String(encodingToHex: .init(rebasing: buffer[8..<10]))
            result += "-"
            result += String(encodingToHex: .init(rebasing: buffer[10...]))
        }
        return result
    }

    public init?(uuidString: String) {
        var bytesCount: Int { return 36 }
        guard uuidString.count == bytesCount else {
            return nil
        }
        let parts = uuidString.split(separator: "-")
        guard parts.count == 5 else {
            return nil
        }

        guard let timeLow = UInt32(parts[0], radix: 16),
            let timeMid = UInt16(parts[1], radix: 16),
            let timeHiWithVersion = UInt16(parts[2], radix: 16),
            let clock = UInt16(parts[3], radix: 16),
            let node = UInt64(parts[4], radix: 16) else {
                return nil
        }

        self = UUID(
            time: .init(
                low: timeLow,
                mid: timeMid,
                hiWithVersion: timeHiWithVersion),
            clock: .init(clock),
            node: .init(node))
    }
}

extension UUID: CustomDebugStringConvertible {
    public var debugDescription: String {
        return uuidString
    }
}
