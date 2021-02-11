import Test

@testable import UInt24

test.case("UInt24") {
    expect(MemoryLayout<UInt24>.size == 3)

    let hight = UInt24(UInt(0xFF) << 16 )
    let middle = UInt24(UInt(0xFF << 8))
    let low = UInt24(UInt(0xFF))

    expect(UInt(hight) == 0xFF << 16)
    expect(UInt(middle) == 0xFF << 8)
    expect(UInt(low) == 0xFF)
}

test.case("UInt24Max") {
    let max = UInt24(UInt(0xFFFFFF))
    expect(UInt(max) == 0xFFFFFF)
}

test.case("UInt24Overflow") {
    // FIXME: how to test a trap?
    // assertThrowsError(UInt24(UInt(0xFFFFFF)+1))
}

test.case("BytesSwapped") {
    expect(UInt24(0xFF0000).byteSwapped == 0x0000FF)
}

test.case("Description") {
    expect(UInt24(0xFF0000).description == UInt(0xFF0000).description)
}

test.run()
