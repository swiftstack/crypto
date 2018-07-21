public struct UInt24: Hashable {
    fileprivate let low: UInt8
    fileprivate let middle: UInt8
    fileprivate let hight: UInt8
}

extension UInt24: Equatable {
    public static func ==(lhs: UInt24, rhs: UInt24) -> Bool {
        return lhs.low == rhs.low
            && lhs.middle == rhs.middle
            && lhs.hight == rhs.hight
    }
}

extension UInt {
    init(_ value: UInt24) {
        self =
            (UInt(value.hight) << 16) |
            (UInt(value.middle) << 8) |
            (UInt(value.low))
    }
}

extension Int {
    init(_ value: UInt24) {
        self =
            (Int(value.hight) << 16) |
            (Int(value.middle) << 8) |
            (Int(value.low))
    }
}

extension UInt24 {
    public init(_ value: Int) {
        self.init(UInt(value))
    }

    public init<T: BinaryInteger>(_ source: T) {
        precondition(source <= 0xFFFFFF)
        self.init(_truncatingBits: UInt(source))
    }

    public init<T: FixedWidthInteger>(truncatingIfNeeded source: T) {
        self.init(_truncatingBits: UInt(source))
    }

    public init(_truncatingBits value: UInt) {
        hight = UInt8(truncatingIfNeeded: value >> 16)
        middle = UInt8(truncatingIfNeeded: value >> 8)
        low = UInt8(truncatingIfNeeded: value)
    }
}

extension UInt24 {
    public static var isSigned: Bool {
        return false
    }

    public static var bitWidth: Int {
        return UInt8.bitWidth * 3
    }

    public var words: [UInt] {
        return [UInt(self)]
    }

    public var byteSwapped: UInt24 {
        return UInt24(low: self.hight, middle: self.middle, hight: self.low)
    }

    public var bigEndian: UInt24 {
        #if _endian(big)
        return self
        #else
        return self.byteSwapped
        #endif
    }

    public var littleEndian: UInt24 {
        #if _endian(little)
        return self
        #else
        return self.byteSwapped
        #endif
    }
}

extension UInt24: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: UInt) {
        self = UInt24(value)
    }
}

extension UInt24: CustomStringConvertible {
    public var description: String {
        return UInt(self).description
    }
}

extension UInt24: Numeric {
    public var magnitude: UInt24 {
        fatalError("unimplemented")
    }

    public static func + (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func += (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    public static func - (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func -= (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    public static func * (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func *= (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    public init?<T>(exactly source: T) where T : BinaryInteger {
        fatalError("unimplemented")
    }
}

    public init?<T>(exactly source: T) where T : BinaryFloatingPoint {
        fatalError("unimplemented")
    }

    public init<T>(_ source: T) where T : BinaryFloatingPoint {
        fatalError("unimplemented")
    }

    public init<T>(clamping source: T) where T : BinaryInteger {
        fatalError("unimplemented")
    }

extension UInt24: UnsignedInteger {
    public var trailingZeroBitCount: Int {
        fatalError("unimplemented")
    }

    public static func / (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func /= (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    public static func % (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func %= (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    prefix public static func ~ (x: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func & (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func &= (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    public static func | (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func |= (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    public static func ^ (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func ^= (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    public static func >> <RHS>(lhs: UInt24, rhs: RHS) -> UInt24
        where RHS : BinaryInteger
    {
        fatalError("unimplemented")
    }

    public static func >>= <RHS>(lhs: inout UInt24, rhs: RHS)
        where RHS : BinaryInteger
    {
        fatalError("unimplemented")
    }

    public static func << <RHS>(lhs: UInt24, rhs: RHS) -> UInt24
        where RHS : BinaryInteger
    {
        fatalError("unimplemented")
    }

    public static func <<= <RHS>(lhs: inout UInt24, rhs: RHS)
        where RHS : BinaryInteger
    {
        fatalError("unimplemented")
    }

    public func quotientAndRemainder(dividingBy rhs: UInt24)
        -> (quotient: UInt24, remainder: UInt24)
    {
        fatalError("unimplemented")
    }

    public func signum() -> UInt24 {
        fatalError("unimplemented")
    }
}

extension UInt24: FixedWidthInteger {
    public static var max: UInt24 {
        fatalError("unimplemented")
    }

    public static var min: UInt24 {
        fatalError("unimplemented")
    }

    public func addingReportingOverflow(_ rhs: UInt24)
        -> (partialValue: UInt24, overflow: Bool)
    {
        fatalError("unimplemented")
    }

    public func subtractingReportingOverflow(_ rhs: UInt24)
        -> (partialValue: UInt24, overflow: Bool)
    {
        fatalError("unimplemented")
    }

    public func multipliedReportingOverflow(by rhs: UInt24)
        -> (partialValue: UInt24, overflow: Bool)
    {
        fatalError("unimplemented")
    }

    public func dividedReportingOverflow(by rhs: UInt24)
        -> (partialValue: UInt24, overflow: Bool)
    {
        fatalError("unimplemented")
    }

    public func remainderReportingOverflow(dividingBy rhs: UInt24)
        -> (partialValue: UInt24, overflow: Bool)
    {
        fatalError("unimplemented")
    }

    public func multipliedFullWidth(by other: UInt24)
        -> (high: UInt24, low: UInt24.Magnitude)
    {
        fatalError("unimplemented")
    }

    public func dividingFullWidth(
        _ dividend: (high: UInt24, low: UInt24.Magnitude))
        -> (quotient: UInt24, remainder: UInt24)
    {
        fatalError("unimplemented")
    }

    public var nonzeroBitCount: Int {
        fatalError("unimplemented")
    }

    public var leadingZeroBitCount: Int {
        fatalError("unimplemented")
    }

    public init(bigEndian value: UInt24) {
        fatalError("unimplemented")
    }

    public init(littleEndian value: UInt24) {
        fatalError("unimplemented")
    }

    public static func &>> (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func &>>= (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    public static func &<< (lhs: UInt24, rhs: UInt24) -> UInt24 {
        fatalError("unimplemented")
    }

    public static func &<<= (lhs: inout UInt24, rhs: UInt24) {
        fatalError("unimplemented")
    }

    public init<T: FixedWidthInteger>(clamping source: T) {
        fatalError("unimplemented")
    }
}
