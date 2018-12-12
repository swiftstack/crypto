import Test
import Time
import ASN1
@testable import X509

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
            let version = try Version(from: asn1)
            assertEqual(version, .v3)
        }
    }

    func testSerialNumber() {
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
            assertEqual(serialNumber.bytes, serialNumberBytes)
        }
    }

    func testTime() {
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
            assertEqual(time, .utc(Time(1368706755.0)))
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
            assertEqual(time, .generalized(Time(1368706755.0)))
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

            let validity = try Validity(from: asn1)
            assertEqual(validity.notBefore, .utc(Time(1368706755.0)))
            assertEqual(validity.notAfter, .utc(Time(1368879555.0)))
        }
    }

    func testName() {
        scope {
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
            assertEqual(name, .rdnSequence(RDNSequence([
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
    }

    func testAttributeTypeAndValue() {
        scope {
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
            assertEqual(typeValue, .init(
                type: .attribute(.countryName),
                value: .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .printableString),
                    content: .string("RU"))))
        }
    }

    func testDirectoryString() {
        scope {
            let directoryString = try DirectoryString(from: .init(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .printableString),
                content: .string("RU")))
            assertEqual(directoryString, .printableString("RU"))
        }
    }

    func testOtherName() {
        scope {
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
            assertEqual(otherName, .init(
                type: .attribute(.commonName),
                value: .init(
                    identifier: .init(
                        isConstructed: false,
                        class: .universal,
                        tag: .utf8String),
                    content: .string("Unique Name"))))
        }
    }
}
