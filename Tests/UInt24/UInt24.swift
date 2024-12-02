import Testing

@testable import UInt24

@Test("UInt24")
private func uint24() async throws {
    #expect(MemoryLayout<UInt24>.size == 3)

    let hight = UInt24(UInt(0xFF) << 16 )
    let middle = UInt24(UInt(0xFF << 8))
    let low = UInt24(UInt(0xFF))

    #expect(UInt(hight) == 0xFF << 16)
    #expect(UInt(middle) == 0xFF << 8)
    #expect(UInt(low) == 0xFF)
}

@Test("UInt24Max")
private func uint24Max() async throws {
    let max = UInt24(UInt(0xFFFFFF))
    #expect(UInt(max) == 0xFFFFFF)
}

@Test("UInt24Overflow")
private func uint24Overflow() async throws {
    // FIXME: how to test a trap?
    // assertThrowsError(UInt24(UInt(0xFFFFFF)+1))
}

@Test("BytesSwapped")
private func bytesSwapped() async throws {
    #expect(UInt24(0xFF0000).byteSwapped == 0x0000FF)
}

@Test("Description")
private func description() async throws {
    #expect(UInt24(0xFF0000).description == UInt(0xFF0000).description)
}
