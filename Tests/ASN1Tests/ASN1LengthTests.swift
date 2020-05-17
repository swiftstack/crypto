import Test
import Stream
@testable import ASN1

class ASN1LengthTests: TestCase {
    func testReadLength1Octet() {
        scope {
            let length = try ASN1.Length(from: InputByteStream([0x81, 0x01]))
            expect(length.value == 1)
        }
    }

    func testReadLength2Octets() {
        scope {
            let length = try ASN1.Length(
                from: InputByteStream([0x82, 0x00, 0x01]))
            expect(length.value == 1)
        }
    }

    func testReadLength4Octets() {
        scope {
            let length = try ASN1.Length(
                from: InputByteStream([0x84, 0x00, 0x00, 0x00, 0x01]))
            expect(length.value == 1)
        }
    }
}
