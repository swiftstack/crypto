import Test
import ASN1
@testable import X509

class ExtensionDecodeTests: TestCase {
    typealias CRLDistributionPoints = Extension.CRLDistributionPoints
    typealias DistributionPoint = CRLDistributionPoints.DistributionPoint
    typealias Reasons = DistributionPoint.Reasons
    typealias KeyUsage = Extension.KeyUsage
    typealias AuthorityKeyIdentifier = Extension.AuthorityKeyIdentifier
    typealias KeyIdentifier = Extension.KeyIdentifier

    func testReasons() {
        scope {
            let reasons = try Reasons(from: .init(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .bitString),
                content: .data([
                    0b1000_0000, 0b1111_1111
                ])))
            assertTrue(reasons.contains(.unused))
            assertTrue(reasons.contains(.keyCompromise))
            assertTrue(reasons.contains(.caCompromise))
            assertTrue(reasons.contains(.affiliationChanged))
            assertTrue(reasons.contains(.superseded))
            assertTrue(reasons.contains(.cessationOfOperation))
            assertTrue(reasons.contains(.certificateHold))
            assertTrue(reasons.contains(.privilegeWithdrawn))
            assertTrue(reasons.contains(.aaCompromise))
        }
    }

    func testKeyUsageExtension() {
        scope {
            let keyUsageExtension = try Extension(from: .init(
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
                ])))
            assertEqual(keyUsageExtension.id, .certificateExtension(.keyUsage))
            assertEqual(keyUsageExtension.isCritical, true)
            guard case .keyUsage(_) = keyUsageExtension.value else {
                fail()
                return
            }
        }
    }

    func testKeyUsage() {
        scope {
            let keyUsage = try KeyUsage(from: .init(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .bitString),
                content: .data([0x05, 0xa0])))
            assertTrue(keyUsage.contains(.digitalSignature))
            assertFalse(keyUsage.contains(.nonRepudiation))
            assertTrue(keyUsage.contains(.keyEncipherment))
            assertFalse(keyUsage.contains(.dataEncipherment))
            assertFalse(keyUsage.contains(.keyAgreement))
            assertFalse(keyUsage.contains(.keyCertSign))
            assertFalse(keyUsage.contains(.crlSign))
            assertFalse(keyUsage.contains(.encipherOnly))
            assertFalse(keyUsage.contains(.decipherOnly))
        }

        scope {
            let keyUsage = try KeyUsage(from: .init(
                identifier: .init(
                    isConstructed: false,
                    class: .universal,
                    tag: .bitString),
                content: .data([0x01, 0x06])))
            assertFalse(keyUsage.contains(.digitalSignature))
            assertFalse(keyUsage.contains(.nonRepudiation))
            assertFalse(keyUsage.contains(.keyEncipherment))
            assertFalse(keyUsage.contains(.dataEncipherment))
            assertFalse(keyUsage.contains(.keyAgreement))
            assertTrue(keyUsage.contains(.keyCertSign))
            assertTrue(keyUsage.contains(.crlSign))
            assertFalse(keyUsage.contains(.encipherOnly))
            assertFalse(keyUsage.contains(.decipherOnly))
        }
    }

    func testExtKeyUsage() {
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
                            .certificateExtension(.extKeyUsage))),
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .octetString),
                        content: .data([
                            0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
                            0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06,
                            0x01, 0x05, 0x05, 0x07, 0x03, 0x02
                        ]))
                ]))
            let expected: Extension = .init(
                id: .certificateExtension(.extKeyUsage),
                isCritical: false,
                value: .extKeyUsage(.init(keyPurposeIds: [
                    .other([43, 6, 1, 5, 5, 7, 3, 1]),
                    .other([43, 6, 1, 5, 5, 7, 3, 2])])))
            let extKeyUsage: Extension = try .init(from: asn1)
            assertEqual(extKeyUsage, expected)
        }
    }

    func testAuthorityKeyIdentifierExtension() {
        scope {
            let authorityKeyIdentifierExtension = try Extension(from: .init(
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
                            .certificateExtension(.authorityKeyIdentifier))),
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .octetString),
                        content: .data([
                            0x30, 0x16, 0x80, 0x14, 0x37, 0x5c, 0xe3, 0x19,
                            0xe0, 0xb2, 0x8e, 0xa1, 0xa8, 0x4e, 0xd2, 0xcf,
                            0xab, 0xd0, 0xdc, 0xe3, 0x0b, 0x5c, 0x35, 0x4d
                        ]))
                ])))
            switch authorityKeyIdentifierExtension.value {
                case .authorityKeyIdentifier(_): break
                default: fail("invalid authorityKeyIdentifierExtension")
            }
        }
    }

    func testAuthorityKeyIdentifier() {
        scope {
            let authorityKeyIdentifier = try AuthorityKeyIdentifier(from: .init(
                identifier: .init(
                    isConstructed: true,
                    class: .universal,
                    tag: .sequence),
                content: .sequence([
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .contextSpecific,
                            tag: .endOfContent),
                        content: .data([
                            0x37, 0x5c, 0xe3, 0x19, 0xe0, 0xb2, 0x8e, 0xa1,
                            0xa8, 0x4e, 0xd2, 0xcf, 0xab, 0xd0, 0xdc, 0xe3,
                            0x0b, 0x5c, 0x35, 0x4d]))
                ])))
            assertNotNil(authorityKeyIdentifier.keyIdentifier)
            assertEqual(
                authorityKeyIdentifier.keyIdentifier,
                KeyIdentifier(rawValue: [
                    0x37, 0x5c, 0xe3, 0x19, 0xe0, 0xb2, 0x8e, 0xa1,
                    0xa8, 0x4e, 0xd2, 0xcf, 0xab, 0xd0, 0xdc, 0xe3,
                    0x0b, 0x5c, 0x35, 0x4d]))
        }
    }

    func testCertificatePoliciesExtension() {
        scope {
            let asn1 = try ASN1(
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
                        content:
                            .objectIdentifier(
                                .certificateExtension(
                                    .certificatePolicies(nil)))),
                    .init(
                        identifier: .init(
                            isConstructed: false,
                            class: .universal,
                            tag: .octetString),
                        content: .data([
                            0x30, 0x82, 0x01, 0x32, 0x30, 0x82, 0x01, 0x2e,
                            0x06, 0x0c, 0x2a, 0x84, 0x68, 0x01, 0x86, 0xf6,
                            0x77, 0x02, 0x05, 0x01, 0x0a, 0x02, 0x30, 0x82,
                            0x01, 0x1c, 0x30, 0x25, 0x06, 0x08, 0x2b, 0x06,
                            0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x19,
                            0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
                            0x77, 0x77, 0x77, 0x2e, 0x63, 0x65, 0x72, 0x74,
                            0x75, 0x6d, 0x2e, 0x70, 0x6c, 0x2f, 0x43, 0x50,
                            0x53, 0x30, 0x81, 0xf2, 0x06, 0x08, 0x2b, 0x06,
                            0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x30, 0x81,
                            0xe5, 0x30, 0x20, 0x16, 0x19, 0x55, 0x6e, 0x69,
                            0x7a, 0x65, 0x74, 0x6f, 0x20, 0x54, 0x65, 0x63,
                            0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65,
                            0x73, 0x20, 0x53, 0x2e, 0x41, 0x2e, 0x30, 0x03,
                            0x02, 0x01, 0x02, 0x1a, 0x81, 0xc0, 0x55, 0x73,
                            0x61, 0x67, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74,
                            0x68, 0x69, 0x73, 0x20, 0x63, 0x65, 0x72, 0x74,
                            0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20,
                            0x69, 0x73, 0x20, 0x73, 0x74, 0x72, 0x69, 0x63,
                            0x74, 0x6c, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6a,
                            0x65, 0x63, 0x74, 0x65, 0x64, 0x20, 0x74, 0x6f,
                            0x20, 0x74, 0x68, 0x65, 0x20, 0x43, 0x45, 0x52,
                            0x54, 0x55, 0x4d, 0x20, 0x43, 0x65, 0x72, 0x74,
                            0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
                            0x6e, 0x20, 0x50, 0x72, 0x61, 0x63, 0x74, 0x69,
                            0x63, 0x65, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65,
                            0x6d, 0x65, 0x6e, 0x74, 0x20, 0x28, 0x43, 0x50,
                            0x53, 0x29, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x72,
                            0x70, 0x6f, 0x72, 0x61, 0x74, 0x65, 0x64, 0x20,
                            0x62, 0x79, 0x20, 0x72, 0x65, 0x66, 0x65, 0x72,
                            0x65, 0x6e, 0x63, 0x65, 0x20, 0x68, 0x65, 0x72,
                            0x65, 0x69, 0x6e, 0x20, 0x61, 0x6e, 0x64, 0x20,
                            0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72,
                            0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72,
                            0x79, 0x20, 0x61, 0x74, 0x20, 0x68, 0x74, 0x74,
                            0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77,
                            0x2e, 0x63, 0x65, 0x72, 0x74, 0x75, 0x6d, 0x2e,
                            0x70, 0x6c, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73,
                            0x69, 0x74, 0x6f, 0x72, 0x79, 0x2e
                        ]))
                ]))
            let certificatePoliciesExtension = try Extension(from: asn1)
            assertEqual(
                certificatePoliciesExtension,
                Extension(
                    id: .certificateExtension(.certificatePolicies(nil)),
                    isCritical: false,
                    value: .certificatePolicies([
                        .init(
                            identifier: .other([
                                42, 132, 104, 1, 134, 246,
                                119, 2, 5, 1, 10, 2
                            ]),
                            qualifiers: [
                                .cps("https://www.certum.pl/CPS"),
                                .unotice(.init(
                                    reference: .init(
                                        organization: .ia5String(
                                            "Unizeto Technologies S.A."),
                                        noticeNumbers: [2]),
                                    explicitText: .visibleString(
                                        "Usage of this certificate is " +
                                        "strictly subjected to the CERTUM " +
                                        "Certification Practice Statement " +
                                        "(CPS) incorporated by reference " +
                                        "herein and in the repository at " +
                                        "https://www.certum.pl/repository.")))
                            ])])))

        }
    }
}
