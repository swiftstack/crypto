import Test
@testable import ASN1

class ASN1EncodeTests: TestCase {
    func testUniversalSequence() {
        scope {
            let identifier = ASN1.Identifier(
                isConstructed: true,
                class: .universal,
                tag: .sequence)
            let bytes = try identifier.encode()
            assertEqual(bytes, [0x30])
        }
    }

    func testContextSpecificEndOfContent() {
        scope {
            let identifier = ASN1.Identifier(
                isConstructed: true,
                class: .contextSpecific,
                tag: .endOfContent)
            let bytes = try identifier.encode()
            assertEqual(bytes, [0xa0])
        }
    }

    func testContentBoolean() {
        scope {
            let asnFalse = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .boolean),
                content: .boolean(false))

            let asnTrue = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .boolean),
                content: .boolean(true))

            let falseBytes = try asnFalse.encode()
            let trueBytes = try asnTrue.encode()

            assertEqual(falseBytes, [0x01, 0x01, 0x00])
            assertEqual(trueBytes, [0x01, 0x01, 0xff])
        }
    }

    func testContentEnumerated() {
        scope {
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .enumerated),
                content: .integer(.sane(0)))
            let bytes = try asn1.encode()
            assertEqual(bytes, [0x0a, 0x01, 0x00])
        }
    }

    func testContentData() {
        scope {
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .objectIdentifier),
                content: .data([43, 6, 1, 5, 5, 7, 48, 1, 1]))
            let bytes = try asn1.encode()
            let expected: [UInt8] = [
                0x06, 0x09,
                0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]
            assertEqual(bytes, expected)
        }
    }

    func testContentSequence() {
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
                            tag: .enumerated),
                        content: .integer(.sane(0))),
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .enumerated),
                        content: .integer(.sane(0)))
                    ]))
            let bytes = try asn1.encode()
            let expected: [UInt8] = [
                0x30, 0x06,
                0x0a, 0x01, 0x00,
                0x0a, 0x01, 0x00]
            assertEqual(bytes, expected)
        }
    }

    func testContentPrintableString() {
        scope {
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .printableString),
                content: .string("RU"))
            let bytes = try asn1.encode()
            assertEqual(bytes, [0x13, 0x02, 0x52, 0x55])
        }
    }

    func testContentUTF8String() {
        scope {
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .utf8String),
                content: .string("Certum Validation Service"))
            let bytes = try asn1.encode()
            let expected: [UInt8] = [
                0x0c, 0x19,
                0x43, 0x65, 0x72, 0x74, 0x75, 0x6d, 0x20, 0x56,
                0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f,
                0x6e, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
                0x65]
            assertEqual(bytes, expected)
        }
    }
}
