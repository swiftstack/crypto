import Test
@testable import ASN1

class ASN1DescriptionTests: TestCase {
    func testSimpleDescription() {
        scope {
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .null),
                content: .data([]))

            let expected = """
                .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .null),
                    content: .data([]))
                """
            assertEqual(asn1.description, expected)
        }
    }

    func testComplexDescription() {
        scope {
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: true,
                    class: .universal,
                    tag: .sequence),
                content: .sequence([
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .objectIdentifier),
                        content: .objectIdentifier(
                            .certificateExtension(.keyUsage))),
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .boolean),
                        content: .boolean(true)),
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .octetString),
                        content: .data([0x03, 0x02, 0x05, 0xa0]))
                ]))

            let expected = """
                .init(
                    identifier: .init(
                        isConstructed: true,
                        class: .universal,
                        tag: .sequence),
                    content: .sequence([
                        .init(
                            identifier: .init(
                                isConstructed: false,
                                class: .universal,
                                tag: .objectIdentifier),
                            content: .objectIdentifier(.certificateExtension(.keyUsage))),
                        .init(
                            identifier: .init(
                                isConstructed: false,
                                class: .universal,
                                tag: .boolean),
                            content: .boolean(true)),
                        .init(
                            identifier: .init(
                                isConstructed: false,
                                class: .universal,
                                tag: .octetString),
                            content: .data([030205a0]))
                    ]))
                """
            assertEqual(asn1.description, expected)
        }
    }
}
