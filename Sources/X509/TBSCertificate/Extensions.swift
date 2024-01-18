import ASN1
import Stream

public struct Extensions: Equatable {
    var items: [Extension]

    init(_ items: [Extension]) {
        self.items = items
    }
}

public struct Extension: Equatable {
    var id: ASN1.ObjectIdentifier
    var isCritical: Bool
    var value: Variant

    enum Variant: Equatable {
    // id-ce-*
    case subjectKeyIdentifier(SubjectKeyIdentifier)
    case keyUsage(KeyUsage)
    case subjectAltName(SubjectAltName)
    case extKeyUsage(ExtendedKeyUsage)
    case basicConstrains(BasicConstrains)
    case crlDistributionPoints(CRLDistributionPoints)
    case authorityKeyIdentifier(AuthorityKeyIdentifier)
    case certificatePolicies(CertificatePolicies)
    // id-pe-*
    case authorityInfoAccessMethod(AuthorityInfoAccess)
    // netscape
    case netscape(Netscape)
    }

    public enum Netscape: Equatable {
        case certificateType(CertificateType)
    }
}

extension Extensions: ExpressibleByArrayLiteral {
    public init(arrayLiteral elemens: Extension...) {
        self.items = elemens
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.2

extension Extensions {
    // Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
    public static func decode(from asn1: ASN1) async throws -> Self {
        guard
            let contextSpecific = asn1.sequenceValue,
            let container = contextSpecific.first,
            let sequence = container.sequenceValue
        else {
            throw Error.invalidASN1(asn1)
        }
        var items: [Extension] = []
        for item in sequence {
            try await items.append(Extension.decode(from: item))
        }
        return .init(items)
    }
}

extension Extension {
    // Extension  ::=  SEQUENCE  {
    //   extnID      OBJECT IDENTIFIER,
    //   critical    BOOLEAN DEFAULT FALSE,
    //   extnValue   OCTET STRING
    //               -- contains the DER encoding of an ASN.1 value
    //               -- corresponding to the extension type identified
    //               -- by extnID
    //   }
    public static func decode(from asn1: ASN1) async throws -> Self {
        guard
            let values = asn1.sequenceValue,
            values.count >= 2 && values.count <= 3,
            let id = values[0].objectIdentifierValue
        else {
            throw Error.invalidASN1(asn1)
        }

        let isCritical: Bool

        if values.count == 2 {
            isCritical = false
        } else {
            guard let _isCritical = values[1].booleanValue else {
                throw Error.invalidASN1(asn1)
            }
            isCritical = _isCritical
        }

        guard let bytes = values.last?.dataValue else {
            throw Error.invalidASN1(asn1)
        }
        let value = try await ASN1.decode(from: bytes)

        let variant: Variant

        switch id {
        case .certificateExtension(.some(.subjectKeyIdentifier)):
            variant = .subjectKeyIdentifier(try .init(from: value))
        case .certificateExtension(.some(.keyUsage)):
            variant = .keyUsage(try .init(from: value))
        case .certificateExtension(.some(.subjectAltName)):
            variant = .subjectAltName(try .init(from: value))
        case .certificateExtension(.some(.extKeyUsage)):
            variant = .extKeyUsage(try .init(from: value))
        case .certificateExtension(.some(.basicConstrains)):
            variant = .basicConstrains(try .init(from: value))
        case .certificateExtension(.some(.crlDistributionPoints)):
            variant = .crlDistributionPoints(try .init(from: value))
        case .certificateExtension(.some(.authorityKeyIdentifier)):
            variant = .authorityKeyIdentifier(try .init(from: value))
        case .pkix(.some(.extension(.authorityInfoAccessSyntax))):
            variant = .authorityInfoAccessMethod(try .init(from: value))
        case .certificateExtension(.some(.certificatePolicies)):
            variant = .certificatePolicies(try .init(from: value))
        case .netscape(.some(.certificateExtension(.certificateType))):
            variant = .netscape(.certificateType(try .init(from: value)))
        default:
            throw Error.unimplemented(asn1)
        }

        return .init(id: id, isCritical: isCritical, value: variant)
    }
}
