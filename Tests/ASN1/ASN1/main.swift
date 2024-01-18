import Test
import Stream

@testable import ASN1

test("EqualityBug") {
    let identifier1 = ASN1.Identifier(
        isConstructed: true,
        class: .contextSpecific,
        tag: .endOfContent)

    let identifier2 = ASN1.Identifier(
        isConstructed: true,
        class: .universal,
        tag: .sequence)

    expect(identifier1 != identifier2)
}

await run()
