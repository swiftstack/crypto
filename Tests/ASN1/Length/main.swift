import Test
import Stream

@testable import ASN1

test.case("ReadLength1Octet") {
    let length = try await ASN1.Length.decode(from: InputByteStream([0x81, 0x01]))
    expect(length.value == 1)
}

test.case("ReadLength2Octets") {
    let length = try await ASN1.Length.decode(
        from: InputByteStream([0x82, 0x00, 0x01]))
    expect(length.value == 1)
}

test.case("ReadLength4Octets") {
    let length = try await ASN1.Length.decode(
        from: InputByteStream([0x84, 0x00, 0x00, 0x00, 0x01]))
    expect(length.value == 1)
}

test.run()
