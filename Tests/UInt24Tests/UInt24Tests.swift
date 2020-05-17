import Test
@testable import UInt24

class UInt24Tests: TestCase {
    func testUInt24() {
        expect(MemoryLayout<UInt24>.size == 3)

        let hight = UInt24(UInt(0xFF) << 16 )
        let middle = UInt24(UInt(0xFF << 8))
        let low = UInt24(UInt(0xFF))

        expect(UInt(hight) == 0xFF << 16)
        expect(UInt(middle) == 0xFF << 8)
        expect(UInt(low) == 0xFF)
    }

    func testUInt24Max() {
        let max = UInt24(UInt(0xFFFFFF))
        expect(UInt(max) == 0xFFFFFF)
    }

    func testUInt24Overflow() {
        // FIXME: how to test a trap?
        // assertThrowsError(UInt24(UInt(0xFFFFFF)+1))
    }

    func testBytesSwapped() {
        expect(UInt24(0xFF0000).byteSwapped == 0x0000FF)
    }

    func testDescription() {
        expect(UInt24(0xFF0000).description == UInt(0xFF0000).description)
    }
}
