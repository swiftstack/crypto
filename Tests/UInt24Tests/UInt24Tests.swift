import Test
@testable import Crypto

class UInt24Tests: TestCase {
    func testUInt24() {
        assertEqual(MemoryLayout<UInt24>.size, 3)

        let hight = UInt24(UInt(0xFF) << 16 )
        let middle = UInt24(UInt(0xFF << 8))
        let low = UInt24(UInt(0xFF))

        assertEqual(UInt(hight), 0xFF << 16)
        assertEqual(UInt(middle), 0xFF << 8)
        assertEqual(UInt(low), 0xFF)
    }

    func testUInt24Max() {
        let max = UInt24(UInt(0xFFFFFF))
        assertEqual(UInt(max), 0xFFFFFF)
    }

    func testUInt24Overflow() {
        // FIXME: how to test a trap?
        // assertThrowsError(UInt24(UInt(0xFFFFFF)+1))
    }

    func testBytesSwapped() {
        assertEqual(UInt24(0xFF0000).byteSwapped, 0x0000FF)
    }

    func testDescription() {
        assertEqual(UInt24(0xFF0000).description, UInt(0xFF0000).description)
    }
}
