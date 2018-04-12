import Test
import Time
import ASN1
@testable import X509

import Stream

class X509DecodeTests: TestCase {
    func testVersion() {
        scope {
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: true,
                    class: .contextSpecific,
                    tag: .endOfContent),
                content: .sequence([
                    .init(
                        identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .integer),
                        content: .integer(.sane(2)))
                ]))
            let version = try Certificate.Version(from: asn1)
            assertEqual(version, .v3)
        }
    }

    func testSerialNumber() {
        scope {
            let bytes: [UInt8] = [
                0x62, 0xfa, 0x7d, 0x18, 0x39, 0x8c, 0x6e, 0x14,
                0xec, 0x17, 0xc6, 0xfa, 0x50, 0x77, 0x75, 0xdf
            ]

            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .integer),
                content: .integer(.insane(bytes)))

            let serialNumber = try Certificate.SerialNumber(from: asn1)
            assertEqual(serialNumber.bytes, bytes)
        }
    }

    func testIdentifier() {
        scope {
            let bytes: [UInt8] = [
                0x30, 0x7b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
                0x55, 0x04, 0x06, 0x13, 0x02, 0x52, 0x55, 0x31,
                0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a,
                0x0c, 0x0a, 0x59, 0x61, 0x6e, 0x64, 0x65, 0x78,
                0x20, 0x4c, 0x4c, 0x43, 0x31, 0x0c, 0x30, 0x0a,
                0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x49,
                0x54, 0x4f, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03,
                0x55, 0x04, 0x07, 0x0c, 0x06, 0x4d, 0x6f, 0x73,
                0x63, 0x6f, 0x77, 0x31, 0x1b, 0x30, 0x19, 0x06,
                0x03, 0x55, 0x04, 0x08, 0x0c, 0x12, 0x52, 0x75,
                0x73, 0x73, 0x69, 0x61, 0x6e, 0x20, 0x46, 0x65,
                0x64, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
                0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04,
                0x03, 0x0c, 0x12, 0x2a, 0x2e, 0x77, 0x66, 0x61,
                0x72, 0x6d, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65,
                0x78, 0x2e, 0x6e, 0x65, 0x74
            ]
            let asn1 = try ASN1(from: InputByteStream(bytes))
            let identifier = try Certificate.Identifier(from: asn1)
            assertEqual(identifier.name, "*.wfarm.yandex.net")
            assertEqual(identifier.country, "RU")
            assertEqual(identifier.locality, "Moscow")
            assertEqual(identifier.stateOrProvince, "Russian Federation")
            assertEqual(identifier.organization, "Yandex LLC")
            assertEqual(identifier.organizationalUnit, "ITO")
        }
    }

    func testValidity() {
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
                            tag: .utcTime),
                        content: .data([
                            0x31, 0x36, 0x30, 0x35, 0x31, 0x33, 0x31, 0x32,
                            0x31, 0x39, 0x31, 0x35, 0x5a
                        ])),
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .utcTime),
                        content: .data([
                            0x31, 0x38, 0x30, 0x35, 0x31, 0x33, 0x31, 0x32,
                            0x31, 0x39, 0x31, 0x35, 0x5a
                        ]))
                    ]))

            let validity = try Certificate.Validity(from: asn1)
            assertEqual(validity.notBefore, Time(1368706755.0))
            assertEqual(validity.notAfter, Time(1368879555.0))
        }
    }
}
