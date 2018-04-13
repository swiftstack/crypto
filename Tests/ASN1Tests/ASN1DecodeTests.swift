import Test
import Stream
@testable import Crypto

class ASN1DecodeTests: TestCase {
    func testUniversalSequence() {
        scope {
            let identifier = try ASN1.Identifier(from: InputByteStream([0x30]))
            assertEqual(identifier.isConstructed, true)
            assertEqual(identifier.class, .universal)
            assertEqual(identifier.tag, .sequence)
        }
    }

    func testContextSpecificEndOfContent() {
        scope {
            let identifier = try ASN1.Identifier(from: InputByteStream([0xa0]))
            assertEqual(identifier.isConstructed, true)
            assertEqual(identifier.class, .contextSpecific)
            assertEqual(identifier.tag, .endOfContent)
        }
    }

    func testContentEnumerated() {
        scope {
            let result = try ASN1(from: InputByteStream([0x0a, 0x01, 0x00]))
            assertEqual(result.identifier, .init(
                isConstructed: false,
                class: .universal,
                tag: .enumerated))
            assertEqual(result.content, .integer(0))
        }
    }

    func testContentData() {
        scope {
            let result = try ASN1(from: InputByteStream([
                    0x06, 0x09,
                    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]))
            assertEqual(result.identifier, .init(
                isConstructed: false,
                class: .universal,
                tag: .objectIdentifier))
            assertEqual(result.content, .data([43, 6, 1, 5, 5, 7, 48, 1, 1]))
        }
    }

    func testContentSequence() {
        scope {
            let result = try ASN1(from: InputByteStream([
                0x30, 0x06,
                0x0a, 0x01, 0x00,
                0x0a, 0x01, 0x00
            ]))
            assertEqual(result.identifier, .init(
                isConstructed: true,
                class: .universal,
                tag: .sequence))
            assertEqual(result.content, .sequence([
                .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .enumerated),
                    content: .integer(0)),
                .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .enumerated),
                    content: .integer(0))
            ]))
        }
    }

    func testContentPrintableString() {
        scope {
            let result = try ASN1(from: InputByteStream([
                0x13, 0x02, 0x52, 0x55
            ]))
            assertEqual(result.identifier, .init(
                isConstructed: false,
                class: .universal,
                tag: .printableString))
            assertEqual(result.content, .string("RU"))
        }
    }

    func testContentUTF8String() {
        scope {
            let result = try ASN1(from: InputByteStream([
                0x0c, 0x19,
                0x43, 0x65, 0x72, 0x74, 0x75, 0x6d, 0x20, 0x56,
                0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f,
                0x6e, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
                0x65
            ]))
            assertEqual(result.identifier, .init(
                isConstructed: false,
                class: .universal,
                tag: .utf8String))
            assertEqual(result.content, .string("Certum Validation Service"))
        }
    }
}
