import Test
import Time
import ASN1
@testable import X509

class CertificateDecodeTests: TestCase {
    func testVersion() throws {
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
        let version = try Version(from: asn1)
        expect(version == .v3)
    }

    func testSerialNumber() throws {
        scope {
            let serialNumberBytes: [UInt8] = [
                0x62, 0xfa, 0x7d, 0x18, 0x39, 0x8c, 0x6e, 0x14,
                0xec, 0x17, 0xc6, 0xfa, 0x50, 0x77, 0x75, 0xdf
            ]

            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .integer),
                content: .integer(.insane(serialNumberBytes)))

            let serialNumber = try SerialNumber(from: asn1)
            expect(serialNumber.value == .insane(serialNumberBytes))
        }

        scope {
            let asn1 = ASN1(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .integer),
                content: .integer(.sane(65568)))

            let serialNumber = try SerialNumber(from: asn1)
            expect(serialNumber.value == .sane(65568))
        }
    }

    func testTime() throws {
        scope {
            let time = try TimeVariant(from: .init(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .utcTime),
                content: .data([
                    0x31, 0x36, 0x30, 0x35, 0x31, 0x33, 0x31, 0x32,
                    0x31, 0x39, 0x31, 0x35, 0x5a
                ])))
            expect(time == .utc(Time(1368706755.0)))
        }

        scope {
            let time = try TimeVariant(from: .init(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .generalizedTime),
                content: .data([
                    0x31, 0x36, 0x30, 0x35, 0x31, 0x33, 0x31, 0x32,
                    0x31, 0x39, 0x31, 0x35, 0x5a
                ])))
            expect(time == .generalized(Time(1368706755.0)))
        }
    }

    func testValidity() throws {
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

        let validity = try Validity(from: asn1)
        expect(validity.notBefore == .utc(Time(1368706755.0)))
        expect(validity.notAfter == .utc(Time(1368879555.0)))
    }

    func testName() throws {
        let name = try Name(from: .init(
            identifier: .init(
                isConstructed: true,
                class: .universal,
                tag: .sequence),
            content: .sequence([
                .init(
                    identifier: .init(
                        isConstructed: true,
                        class: .universal,
                        tag: .set),
                    content: .sequence([
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
                                        tag: .objectIdentifier
                                    ),
                                    content: .objectIdentifier(
                                        .attribute(.commonName))),
                                .init(
                                    identifier: .init(
                                        isConstructed: false,
                                        class: .universal,
                                        tag: .utf8String),
                                    content: .string("Unique Name"))
                            ]))
                    ])),
            ])))
        expect(name == .rdnSequence(RDNSequence([
            .init([
                .init(
                    type: .attribute(.commonName),
                    value: .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .utf8String),
                        content: .string("Unique Name")))
            ])
        ])))
    }

    func testAttributeTypeAndValue() throws {
        let typeValue = try AttributeTypeAndValue(from: .init(
            identifier: .init(
                isConstructed: true,
                class: .universal,
                tag: .graphicString),
            content: .sequence([
                .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .objectIdentifier),
                    content: .objectIdentifier(.attribute(.countryName))
                ),
                .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .printableString),
                    content: .string("RU")
                )
            ])))
        expect(typeValue == .init(
            type: .attribute(.countryName),
            value: .init(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .printableString),
                content: .string("RU"))))
    }

    func testDirectoryString() throws {
        let directoryString = try DirectoryString(from: .init(
            identifier: .init(
                isConstructed: false,
                class: .universal,
                tag: .printableString),
            content: .string("RU")))
        expect(directoryString == .printableString("RU"))
    }

    func testOtherName() throws {
        let otherName = try OtherName(from: .init(
            identifier: .init(
                isConstructed: true,
                class: .universal,
                tag: .sequence),
            content: .sequence([
                .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .objectIdentifier
                    ),
                    content: .objectIdentifier(
                        .attribute(.commonName))),
                .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .utf8String),
                    content: .string("Unique Name"))
            ])))
        expect(otherName == .init(
            type: .attribute(.commonName),
            value: .init(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .utf8String),
                content: .string("Unique Name"))))
    }

    func testAlgorithmIdentifier() throws {
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
                    content: .objectIdentifier(.rsaEncryption)),
                .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .null),
                    content: .data([]))
            ]))
        let algorithmIdentifier = try AlgorithmIdentifier(from: asn1)
        expect(algorithmIdentifier == .init(
            objectId: .rsaEncryption,
            parameters: nil))
    }

    func testSubjectPublicKeyInfo() throws {
        let asn1 = ASN1(
            identifier: .init(
                isConstructed: true,
                class: .universal,
                tag: .sequence),
                content: .sequence([
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
                                content: .objectIdentifier(.rsaEncryption)),
                            .init(
                                identifier: .init(
                                    isConstructed: false,
                                    class: .universal,
                                    tag: .null),
                                content: .data([]))
                        ])),
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .bitString),
                        content: .data([
                            0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,
                            0x01, 0x00, 0xdf, 0x8b, 0x73, 0x06, 0x95, 0xff,
                            0x53, 0x9a, 0xcb, 0x03, 0xab, 0xd2, 0xe0, 0xfd,
                            0x3e, 0x3e, 0xdb, 0x02, 0x95, 0x0f, 0x85, 0xd0,
                            0x31, 0xfd, 0x44, 0x5e, 0xcb, 0xa9, 0xd0, 0xae,
                            0x57, 0x51, 0x16, 0x3b, 0x18, 0x3e, 0x80, 0xc0,
                            0x57, 0x1f, 0x7c, 0xdb, 0x11, 0x3b, 0x2e, 0x9d,
                            0x47, 0xff, 0xe1, 0x18, 0x41, 0x03, 0xbc, 0xbb,
                            0x51, 0xed, 0x74, 0xd2, 0x77, 0xcf, 0x33, 0xbc,
                            0x59, 0x2e, 0x4b, 0x48, 0xf5, 0x4d, 0x05, 0xe8,
                            0x3e, 0x17, 0x14, 0x95, 0x7d, 0xf9, 0x8c, 0x1c,
                            0x84, 0x2f, 0xfd, 0xae, 0x20, 0xe9, 0xa2, 0x36,
                            0xa5, 0x0b, 0x48, 0xea, 0x78, 0xbb, 0x59, 0xdf,
                            0x76, 0x83, 0xe4, 0x8c, 0x75, 0xe5, 0x29, 0x93,
                            0x91, 0x72, 0xa9, 0x44, 0xd0, 0x7b, 0x14, 0xed,
                            0x8d, 0xe4, 0x71, 0x92, 0x33, 0x60, 0x5b, 0xc0,
                            0xa1, 0x0e, 0xb3, 0x92, 0x7d, 0x96, 0xeb, 0x0f,
                            0x57, 0x9c, 0x1c, 0xff, 0x88, 0x59, 0xc9, 0x38,
                            0x19, 0x86, 0x55, 0x3e, 0xf7, 0xd0, 0x54, 0x15,
                            0x1e, 0x34, 0xc1, 0x2e, 0x67, 0x6e, 0x6d, 0x36,
                            0xb3, 0x9e, 0xdd, 0x96, 0x24, 0x5d, 0xdc, 0x5e,
                            0x7e, 0x41, 0xcb, 0x7d, 0x33, 0x10, 0x94, 0x3e,
                            0x52, 0xcb, 0x3f, 0xbd, 0x11, 0x21, 0xf6, 0xd4,
                            0x89, 0xac, 0xdd, 0xb7, 0xa4, 0x17, 0x0d, 0x2f,
                            0xd5, 0xb4, 0xba, 0x59, 0x8d, 0x52, 0x9e, 0x7c,
                            0xc1, 0xd4, 0x99, 0xfa, 0x51, 0xb7, 0xfc, 0x93,
                            0x98, 0x52, 0x7d, 0xb5, 0x15, 0x8a, 0xe8, 0xb5,
                            0x36, 0x66, 0x0e, 0x2b, 0xdf, 0xf1, 0x8b, 0x55,
                            0x9e, 0xeb, 0xcf, 0xd3, 0xb0, 0x4e, 0xb1, 0x8c,
                            0x47, 0x40, 0xc5, 0xc9, 0x61, 0x16, 0x8e, 0xb1,
                            0xfb, 0x42, 0x1c, 0x62, 0xcb, 0x79, 0xdd, 0x5d,
                            0x3d, 0x6a, 0x87, 0xfd, 0xc1, 0x32, 0x41, 0x04,
                            0xd7, 0x29, 0x6c, 0xf2, 0x3f, 0x3e, 0x28, 0x74,
                            0xb7, 0xdb, 0x02, 0x03, 0x01, 0x00, 0x01]))
                ]))

        let publicKey = try PublicKey(from: asn1)
        expect(publicKey == .rsa(.init(
            modulus: [
                0x00, 0xdf, 0x8b, 0x73, 0x06, 0x95, 0xff, 0x53,
                0x9a, 0xcb, 0x03, 0xab, 0xd2, 0xe0, 0xfd, 0x3e,
                0x3e, 0xdb, 0x02, 0x95, 0x0f, 0x85, 0xd0, 0x31,
                0xfd, 0x44, 0x5e, 0xcb, 0xa9, 0xd0, 0xae, 0x57,
                0x51, 0x16, 0x3b, 0x18, 0x3e, 0x80, 0xc0, 0x57,
                0x1f, 0x7c, 0xdb, 0x11, 0x3b, 0x2e, 0x9d, 0x47,
                0xff, 0xe1, 0x18, 0x41, 0x03, 0xbc, 0xbb, 0x51,
                0xed, 0x74, 0xd2, 0x77, 0xcf, 0x33, 0xbc, 0x59,
                0x2e, 0x4b, 0x48, 0xf5, 0x4d, 0x05, 0xe8, 0x3e,
                0x17, 0x14, 0x95, 0x7d, 0xf9, 0x8c, 0x1c, 0x84,
                0x2f, 0xfd, 0xae, 0x20, 0xe9, 0xa2, 0x36, 0xa5,
                0x0b, 0x48, 0xea, 0x78, 0xbb, 0x59, 0xdf, 0x76,
                0x83, 0xe4, 0x8c, 0x75, 0xe5, 0x29, 0x93, 0x91,
                0x72, 0xa9, 0x44, 0xd0, 0x7b, 0x14, 0xed, 0x8d,
                0xe4, 0x71, 0x92, 0x33, 0x60, 0x5b, 0xc0, 0xa1,
                0x0e, 0xb3, 0x92, 0x7d, 0x96, 0xeb, 0x0f, 0x57,
                0x9c, 0x1c, 0xff, 0x88, 0x59, 0xc9, 0x38, 0x19,
                0x86, 0x55, 0x3e, 0xf7, 0xd0, 0x54, 0x15, 0x1e,
                0x34, 0xc1, 0x2e, 0x67, 0x6e, 0x6d, 0x36, 0xb3,
                0x9e, 0xdd, 0x96, 0x24, 0x5d, 0xdc, 0x5e, 0x7e,
                0x41, 0xcb, 0x7d, 0x33, 0x10, 0x94, 0x3e, 0x52,
                0xcb, 0x3f, 0xbd, 0x11, 0x21, 0xf6, 0xd4, 0x89,
                0xac, 0xdd, 0xb7, 0xa4, 0x17, 0x0d, 0x2f, 0xd5,
                0xb4, 0xba, 0x59, 0x8d, 0x52, 0x9e, 0x7c, 0xc1,
                0xd4, 0x99, 0xfa, 0x51, 0xb7, 0xfc, 0x93, 0x98,
                0x52, 0x7d, 0xb5, 0x15, 0x8a, 0xe8, 0xb5, 0x36,
                0x66, 0x0e, 0x2b, 0xdf, 0xf1, 0x8b, 0x55, 0x9e,
                0xeb, 0xcf, 0xd3, 0xb0, 0x4e, 0xb1, 0x8c, 0x47,
                0x40, 0xc5, 0xc9, 0x61, 0x16, 0x8e, 0xb1, 0xfb,
                0x42, 0x1c, 0x62, 0xcb, 0x79, 0xdd, 0x5d, 0x3d,
                0x6a, 0x87, 0xfd, 0xc1, 0x32, 0x41, 0x04, 0xd7,
                0x29, 0x6c, 0xf2, 0x3f, 0x3e, 0x28, 0x74, 0xb7,
                0xdb],
            exponent: 65537)))
    }
}
