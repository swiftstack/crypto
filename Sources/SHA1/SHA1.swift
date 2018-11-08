public struct SHA1 {
    public struct Hash: Equatable {
        public var a,b,c,d,e: UInt32
    }

    var intermediateHash: Hash

    let initialHash: Hash = .init(
        a: 0x67452301,
        b: 0xEFCDAB89,
        c: 0x98BADCFE,
        d: 0x10325476,
        e: 0xC3D2E1F0
    )

    struct Keys {
        static let from0to19: UInt32 = 0x5A827999
        static let from20to39: UInt32 = 0x6ED9EBA1
        static let from40to59: UInt32 = 0x8F1BBCDC
        static let from60to79: UInt32 = 0xCA62C1D6
    }

    typealias Block = (
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32
    )

    let blockSize = 64
    var processed: UInt64 = 0
    var reminder: [UInt8] = []

    public init() {
        intermediateHash = initialHash
        reminder.reserveCapacity(blockSize)
    }

    public mutating func reset() {
        processed = 0
        intermediateHash = initialHash
        reminder.removeAll(keepingCapacity: true)
    }

    public mutating func update(_ bytes: [UInt8]) {
        var bytes = UnsafeRawBufferPointer(
            start: bytes,
            count: bytes.count)

        processed += UInt64(bytes.count) << 3

        if reminder.count > 0 {
            guard bytes.count + reminder.count >= blockSize else {
                reminder.append(contentsOf: bytes)
                return
            }
            reminder.append(
                contentsOf: bytes.prefix(upTo: blockSize - reminder.count))

            transform(UnsafeRawBufferPointer(
                start: reminder,
                count: reminder.count))

            bytes = UnsafeRawBufferPointer(
                rebasing: bytes.suffix(from: blockSize))
            reminder.removeAll(keepingCapacity: true)
        }

        let blocksCount = bytes.count / blockSize
        if blocksCount > 0 {
            let blocksBuffer = UnsafeRawBufferPointer(
                rebasing: bytes.suffix(from: blocksCount * blockSize))
            transform(blocksBuffer)
            bytes = blocksBuffer
        }

        if bytes.count > 0 {
            reminder.append(contentsOf: bytes)
        }
    }

    public mutating func final() -> Hash {
        // there is always room for one
        reminder.append(0x80)
        if reminder.count > blockSize - 8 {
            let endIndex = blockSize - reminder.count
            for _ in 0..<endIndex {
                reminder.append(0)
            }
            transform(UnsafeRawBufferPointer(
                start: reminder,
                count: reminder.count))
            reminder.removeAll(keepingCapacity: true)
        }

        let endIndex = blockSize - reminder.count
        for _ in 0..<endIndex {
            reminder.append(0)
        }

        UnsafeMutableRawPointer(mutating: reminder)
            .advanced(by: blockSize - 8)
            .assumingMemoryBound(to: UInt64.self)
            .pointee = processed.bigEndian

        transform(UnsafeRawBufferPointer(
            start: reminder,
            count: reminder.count))

        defer { reset() }
        return intermediateHash
    }

    @inline(__always)
    func _rotate(_ x: UInt32, leftBy amount: Int) -> UInt32 {
        return (x << UInt32(amount)) | (x >> UInt32(32 - amount))
    }

    @inline(__always)
    func updateX(
        _ a: inout UInt32,
        _ ix: inout UInt32,
        _ ia: UInt32,
        _ ib: UInt32,
        _ ic: UInt32,
        _ id: UInt32
    ) {
        a = _rotate(ia ^ ib ^ ic ^ id, leftBy: 1)
        ix = a
    }

    @inline(__always)
    func from0To15(
        _ i: UInt32,
        _ a: UInt32,
        _ b: inout UInt32,
        _ c: UInt32,
        _ d: UInt32,
        _ e: UInt32,
        _ f: inout UInt32,
        _ xi: UInt32
    ) {
        f = xi &+ e &+ Keys.from0to19 &+ _rotate(a, leftBy: 5)
            &+ (((c ^ d) & b) ^ d)
        b = _rotate(b, leftBy: 30)
    }

    @inline(__always)
    func from16To19(
        _ i: UInt32,
        _ a: UInt32,
        _ b: inout UInt32,
        _ c: UInt32,
        _ d: UInt32,
        _ e: UInt32,
        _ f: inout UInt32,
        _ xi: inout UInt32,
        _ xa: UInt32,
        _ xb: UInt32,
        _ xc: UInt32,
        _ xd: UInt32
    ) {
        updateX(&f, &xi, xa, xb, xc, xd)
        f = f &+ e &+ Keys.from0to19 &+ _rotate(a, leftBy: 5)
            &+ (((c ^ d) & b) ^ d)
        b = _rotate(b, leftBy: 30)
    }

    @inline(__always)
    func from20To31(
        _ i: UInt32,
        _ a: UInt32,
        _ b: inout UInt32,
        _ c: UInt32,
        _ d: UInt32,
        _ e: UInt32,
        _ f: inout UInt32,
        _ xi: inout UInt32,
        _ xa: UInt32,
        _ xb: UInt32,
        _ xc: UInt32,
        _ xd: UInt32
    ) {
        updateX(&f, &xi, xa, xb, xc, xd)
        f = f &+ e &+ Keys.from20to39 &+ _rotate(a, leftBy: 5)
            &+ (b ^ c ^ d)
        b = _rotate(b, leftBy: 30)
    }

    @inline(__always)
    func from32To39(
        _ i: UInt32,
        _ a: UInt32,
        _ b: inout UInt32,
        _ c: UInt32,
        _ d: UInt32,
        _ e: UInt32,
        _ f: inout UInt32,
        _ xa: inout UInt32,
        _ xb: UInt32,
        _ xc: UInt32,
        _ xd: UInt32
    ) {
        updateX(&f, &xa, xa, xb, xc, xd)
        f = f &+ e &+ Keys.from20to39 &+ _rotate(a, leftBy: 5)
            &+ (b ^ c ^ d)
        b = _rotate(b, leftBy: 30)
    }

    @inline(__always)
    func from40To59(
        _ i: UInt32,
        _ a: UInt32,
        _ b: inout UInt32,
        _ c: UInt32,
        _ d: UInt32,
        _ e: UInt32,
        _ f: inout UInt32,
        _ xa: inout UInt32,
        _ xb: UInt32,
        _ xc: UInt32,
        _ xd: UInt32
    ) {
        updateX(&f, &xa, xa, xb, xc, xd)
        f = f &+ e &+ Keys.from40to59 &+ _rotate(a, leftBy: 5)
            &+ ((b & c) | ((b | c) & d))
        b = _rotate(b, leftBy: 30)
    }

    @inline(__always)
    func from60To79(
        _ i: UInt32,
        _ a: UInt32,
        _ b: inout UInt32,
        _ c: UInt32,
        _ d: UInt32,
        _ e: UInt32,
        _ f: inout UInt32,
        _ xa: inout UInt32,
        _ xb: UInt32,
        _ xc: UInt32,
        _ xd: UInt32
    ) {
        updateX(&f, &xa, xa, xb, xc, xd)
        f = xa &+ e &+ Keys.from60to79 &+ _rotate(a, leftBy: 5) &+ (b ^ c ^ d)
        b = _rotate(b, leftBy: 30)
    }

    mutating func transform(_ blocks: UnsafeRawBufferPointer) {
        assert(blocks.count > 0 && blocks.count % blockSize == 0)

        var a = intermediateHash.a
        var b = intermediateHash.b
        var c = intermediateHash.c
        var d = intermediateHash.d
        var e = intermediateHash.e

        var t: UInt32 = 0

        var x = Block(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

        for i in stride(from: 0, to: blocks.count, by: blockSize) {
            let block = UnsafeBufferPointer<UInt32>(
                start: blocks.baseAddress!
                    .advanced(by: i)
                    .assumingMemoryBound(to: UInt32.self),
                count: blockSize / 4 // MemoryLayout<UInt32>.size
            )

            x.0 = block[0].bigEndian
            x.1 = block[1].bigEndian
            from0To15(0, a, &b, c, d, e, &t, x.0)
            x.2 = block[2].bigEndian
            from0To15(1, t, &a, b, c, d, &e, x.1)
            x.3 = block[3].bigEndian
            from0To15(2, e, &t, a, b, c, &d, x.2)
            x.4 = block[4].bigEndian
            from0To15(3, d, &e, t, a, b, &c, x.3)
            x.5 = block[5].bigEndian
            from0To15(4, c, &d, e, t, a, &b, x.4)
            x.6 = block[6].bigEndian
            from0To15(5, b, &c, d, e, t, &a, x.5)
            x.7 = block[7].bigEndian
            from0To15(6, a, &b, c, d, e, &t, x.6)
            x.8 = block[8].bigEndian
            from0To15(7, t, &a, b, c, d, &e, x.7)
            x.9 = block[9].bigEndian
            from0To15(8, e, &t, a, b, c, &d, x.8)
            x.10 = block[10].bigEndian
            from0To15(9, d, &e, t, a, b, &c, x.9)
            x.11 = block[11].bigEndian
            from0To15(10, c, &d, e, t, a, &b, x.10)
            x.12 = block[12].bigEndian
            from0To15(11, b, &c, d, e, t, &a, x.11)
            x.13 = block[13].bigEndian
            from0To15(12, a, &b, c, d, e, &t, x.12)
            x.14 = block[14].bigEndian
            from0To15(13, t, &a, b, c, d, &e, x.13)
            x.15 = block[15].bigEndian
            from0To15(14, e, &t, a, b, c, &d, x.14)
            from0To15(15, d, &e, t, a, b, &c, x.15)

            from16To19(16, c, &d, e, t, a, &b, &x.0, x.0, x.2, x.8, x.13)
            from16To19(17, b, &c, d, e, t, &a, &x.1, x.1, x.3, x.9, x.14)
            from16To19(18, a, &b, c, d, e, &t, &x.2, x.2, x.4, x.10, x.15)
            from16To19(19, t, &a, b, c, d, &e, &x.3, x.3, x.5, x.11, x.0)

            from20To31(20, e, &t, a, b, c, &d, &x.4, x.4, x.6, x.12, x.1)
            from20To31(21, d, &e, t, a, b, &c, &x.5, x.5, x.7, x.13, x.2)
            from20To31(22, c, &d, e, t, a, &b, &x.6, x.6, x.8, x.14, x.3)
            from20To31(23, b, &c, d, e, t, &a, &x.7, x.7, x.9, x.15, x.4)
            from20To31(24, a, &b, c, d, e, &t, &x.8, x.8, x.10, x.0, x.5)
            from20To31(25, t, &a, b, c, d, &e, &x.9, x.9, x.11, x.1, x.6)
            from20To31(26, e, &t, a, b, c, &d, &x.10, x.10, x.12, x.2, x.7)
            from20To31(27, d, &e, t, a, b, &c, &x.11, x.11, x.13, x.3, x.8)
            from20To31(28, c, &d, e, t, a, &b, &x.12, x.12, x.14, x.4, x.9)
            from20To31(29, b, &c, d, e, t, &a, &x.13, x.13, x.15, x.5, x.10)
            from20To31(30, a, &b, c, d, e, &t, &x.14, x.14, x.0, x.6, x.11)
            from20To31(31, t, &a, b, c, d, &e, &x.15, x.15, x.1, x.7, x.12)

            from32To39(32, e, &t, a, b, c, &d, &x.0, x.2, x.8, x.13)
            from32To39(33, d, &e, t, a, b, &c, &x.1, x.3, x.9, x.14)
            from32To39(34, c, &d, e, t, a, &b, &x.2, x.4, x.10, x.15)
            from32To39(35, b, &c, d, e, t, &a, &x.3, x.5, x.11, x.0)
            from32To39(36, a, &b, c, d, e, &t, &x.4, x.6, x.12, x.1)
            from32To39(37, t, &a, b, c, d, &e, &x.5, x.7, x.13, x.2)
            from32To39(38, e, &t, a, b, c, &d, &x.6, x.8, x.14, x.3)
            from32To39(39, d, &e, t, a, b, &c, &x.7, x.9, x.15, x.4)

            from40To59(40, c, &d, e, t, a, &b, &x.8, x.10, x.0, x.5)
            from40To59(41, b, &c, d, e, t, &a, &x.9, x.11, x.1, x.6)
            from40To59(42, a, &b, c, d, e, &t, &x.10, x.12, x.2, x.7)
            from40To59(43, t, &a, b, c, d, &e, &x.11, x.13, x.3, x.8)
            from40To59(44, e, &t, a, b, c, &d, &x.12, x.14, x.4, x.9)
            from40To59(45, d, &e, t, a, b, &c, &x.13, x.15, x.5, x.10)
            from40To59(46, c, &d, e, t, a, &b, &x.14, x.0, x.6, x.11)
            from40To59(47, b, &c, d, e, t, &a, &x.15, x.1, x.7, x.12)
            from40To59(48, a, &b, c, d, e, &t, &x.0, x.2, x.8, x.13)
            from40To59(49, t, &a, b, c, d, &e, &x.1, x.3, x.9, x.14)
            from40To59(50, e, &t, a, b, c, &d, &x.2, x.4, x.10, x.15)
            from40To59(51, d, &e, t, a, b, &c, &x.3, x.5, x.11, x.0)
            from40To59(52, c, &d, e, t, a, &b, &x.4, x.6, x.12, x.1)
            from40To59(53, b, &c, d, e, t, &a, &x.5, x.7, x.13, x.2)
            from40To59(54, a, &b, c, d, e, &t, &x.6, x.8, x.14, x.3)
            from40To59(55, t, &a, b, c, d, &e, &x.7, x.9, x.15, x.4)
            from40To59(56, e, &t, a, b, c, &d, &x.8, x.10, x.0, x.5)
            from40To59(57, d, &e, t, a, b, &c, &x.9, x.11, x.1, x.6)
            from40To59(58, c, &d, e, t, a, &b, &x.10, x.12, x.2, x.7)
            from40To59(59, b, &c, d, e, t, &a, &x.11, x.13, x.3, x.8)

            from60To79(60, a, &b, c, d, e, &t, &x.12, x.14, x.4, x.9)
            from60To79(61, t, &a, b, c, d, &e, &x.13, x.15, x.5, x.10)
            from60To79(62, e, &t, a, b, c, &d, &x.14, x.0, x.6, x.11)
            from60To79(63, d, &e, t, a, b, &c, &x.15, x.1, x.7, x.12)
            from60To79(64, c, &d, e, t, a, &b, &x.0, x.2, x.8, x.13)
            from60To79(65, b, &c, d, e, t, &a, &x.1, x.3, x.9, x.14)
            from60To79(66, a, &b, c, d, e, &t, &x.2, x.4, x.10, x.15)
            from60To79(67, t, &a, b, c, d, &e, &x.3, x.5, x.11, x.0)
            from60To79(68, e, &t, a, b, c, &d, &x.4, x.6, x.12, x.1)
            from60To79(69, d, &e, t, a, b, &c, &x.5, x.7, x.13, x.2)
            from60To79(70, c, &d, e, t, a, &b, &x.6, x.8, x.14, x.3)
            from60To79(71, b, &c, d, e, t, &a, &x.7, x.9, x.15, x.4)
            from60To79(72, a, &b, c, d, e, &t, &x.8, x.10, x.0, x.5)
            from60To79(73, t, &a, b, c, d, &e, &x.9, x.11, x.1, x.6)
            from60To79(74, e, &t, a, b, c, &d, &x.10, x.12, x.2, x.7)
            from60To79(75, d, &e, t, a, b, &c, &x.11, x.13, x.3, x.8)
            from60To79(76, c, &d, e, t, a, &b, &x.12, x.14, x.4, x.9)
            from60To79(77, b, &c, d, e, t, &a, &x.13, x.15, x.5, x.10)
            from60To79(78, a, &b, c, d, e, &t, &x.14, x.0, x.6, x.11)
            from60To79(79, t, &a, b, c, d, &e, &x.15, x.1, x.7, x.12)

            intermediateHash.a = intermediateHash.a &+ e
            intermediateHash.b = intermediateHash.b &+ t
            intermediateHash.c = intermediateHash.c &+ a
            intermediateHash.d = intermediateHash.d &+ b
            intermediateHash.e = intermediateHash.e &+ c

            a = intermediateHash.a
            b = intermediateHash.b
            c = intermediateHash.c
            d = intermediateHash.d
            e = intermediateHash.e
        }
    }
}
