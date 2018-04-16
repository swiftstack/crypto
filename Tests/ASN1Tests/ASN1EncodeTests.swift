import Test
import Stream
@testable import Crypto

class ASN1EncodeTests: TestCase {
    func testUniversalSequence() {
        scope {
            let stream = OutputByteStream()
            let identifier = ASN1.Identifier(
                isConstructed: true,
                class: .universal,
                tag: .sequence)
            try identifier.encode(to: stream)
            assertEqual(stream.bytes, [0x30])
        }
    }

    func testContextSpecificEndOfContent() {
        scope {
            let stream = OutputByteStream()
            let identifier = ASN1.Identifier(
                isConstructed: true,
                class: .contextSpecific,
                tag: .endOfContent)
            try identifier.encode(to: stream)
            assertEqual(stream.bytes, [0xa0])
        }
    }

    func testContentEnumerated() {
        scope {
            let stream = OutputByteStream()
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .enumerated),
                content: .integer(.sane(0)))
            try asn1.encode(to: stream)
            assertEqual(stream.bytes, [0x0a, 0x01, 0x00])
        }
    }

    func testContentData() {
        scope {
            let stream = OutputByteStream()
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .objectIdentifier),
                content: .data([43, 6, 1, 5, 5, 7, 48, 1, 1]))
            try asn1.encode(to: stream)
            let expected: [UInt8] = [
                0x06, 0x09,
                0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]
            assertEqual(stream.bytes, expected)
        }
    }

    func testContentSequence() {
        scope {
            let stream = OutputByteStream()
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
            try asn1.encode(to: stream)
            let expected: [UInt8] = [
                0x30, 0x06,
                0x0a, 0x01, 0x00,
                0x0a, 0x01, 0x00]
            assertEqual(stream.bytes, expected)
        }
    }

    func testContentPrintableString() {
        scope {
            let stream = OutputByteStream()
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .printableString),
                content: .string("RU"))
            try asn1.encode(to: stream)
            assertEqual(stream.bytes, [0x13, 0x02, 0x52, 0x55])
        }
    }

    func testContentUTF8String() {
        scope {
            let stream = OutputByteStream()
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .utf8String),
                content: .string("Certum Validation Service"))
            try asn1.encode(to: stream)
            let expected: [UInt8] = [
                0x0c, 0x19,
                0x43, 0x65, 0x72, 0x74, 0x75, 0x6d, 0x20, 0x56,
                0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f,
                0x6e, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
                0x65]
            assertEqual(stream.bytes, expected)
        }
    }
}
