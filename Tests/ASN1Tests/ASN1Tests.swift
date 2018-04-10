import Test
import Stream
@testable import Crypto

class ASN1Tests: TestCase {
    func testEqualityBug() {
        let identifier1 = ASN1.Identifier(
            isConstructed: true,
            class: .contextSpecific,
            tag: .ber)

        let identifier2 = ASN1.Identifier(
            isConstructed: true,
            class: .universal,
            tag: .sequence)

        assertNotEqual(identifier1, identifier2)
    }
}
