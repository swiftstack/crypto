import Testing
import Stream

@testable import ASN1

@Test("ReadLength1Octet")
private func ReadLength1Octet() async throws {
    let length = try await ASN1.Length.decode(
        from: InputByteStream([0x81, 0x01]))
    #expect(length.value == 1)
}

@Test("ReadLength2Octets")
private func ReadLength2Octets() async throws {
    let length = try await ASN1.Length.decode(
        from: InputByteStream([0x82, 0x00, 0x01]))
    #expect(length.value == 1)
}

@Test("ReadLength4Octets")
private func ReadLength4Octets() async throws {
    let length = try await ASN1.Length.decode(
        from: InputByteStream([0x84, 0x00, 0x00, 0x00, 0x01]))
    #expect(length.value == 1)
}
