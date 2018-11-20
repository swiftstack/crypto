import Test
import Stream
@testable import ASN1

class ASN1Tests: TestCase {
    func testEqualityBug() {
        let identifier1 = ASN1.Identifier(
            isConstructed: true,
            class: .contextSpecific,
            tag: .endOfContent)

        let identifier2 = ASN1.Identifier(
            isConstructed: true,
            class: .universal,
            tag: .sequence)

        assertNotEqual(identifier1, identifier2)
    }
}
