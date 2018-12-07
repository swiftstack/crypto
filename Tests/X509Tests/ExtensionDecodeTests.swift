import Test
import ASN1
@testable import X509

class ExtensionDecodeTests: TestCase {
    typealias Extension = TBSCertificate.Extension
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
}
