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
    public init(from asn1: ASN1) throws {
        guard let contextSpecific = asn1.sequenceValue,
            let container = contextSpecific.first,
            let sequence = container.sequenceValue else
        {
            throw Error.invalidASN1(asn1)
        }
        self.items = try sequence.map(Extension.init)
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
    public init(from asn1: ASN1) throws {
        guard let values = asn1.sequenceValue,
            values.count >= 2 && values.count <= 3,
            let id = values[0].objectIdentifierValue else
        {
            throw Error.invalidASN1(asn1)
        }

        self.id = id

        if values.count == 2 {
            self.isCritical = false
        } else  {
            guard let isCritical = values[1].booleanValue else {
                throw Error.invalidASN1(asn1)
            }
            self.isCritical = isCritical
        }

        guard let bytes = values.last?.dataValue else {
            throw Error.invalidASN1(asn1)
        }
        let value = try ASN1(from: bytes)

        switch id {
        case .certificateExtension(.some(.subjectKeyIdentifier)):
            self.value = .subjectKeyIdentifier(try .init(from: value))
        case .certificateExtension(.some(.keyUsage)):
            self.value = .keyUsage(try .init(from: value))
        case .certificateExtension(.some(.subjectAltName)):
            self.value = .subjectAltName(try .init(from: value))
        case .certificateExtension(.some(.extKeyUsage)):
            self.value = .extKeyUsage(try .init(from: value))
        case .certificateExtension(.some(.basicConstrains)):
            self.value = .basicConstrains(try .init(from: value))
        case .certificateExtension(.some(.crlDistributionPoints)):
            self.value = .crlDistributionPoints(try .init(from: value))
        case .certificateExtension(.some(.authorityKeyIdentifier)):
            self.value = .authorityKeyIdentifier(try .init(from: value))
        case .pkix(.some(.extension(.authorityInfoAccessSyntax))):
            self.value = .authorityInfoAccessMethod(try .init(from: value))
        case .certificateExtension(.some(.certificatePolicies)):
            self.value = .certificatePolicies(try .init(from: value))
        case .netscape(.some(.certificateExtension(.certificateType))):
            self.value = .netscape(.certificateType(try .init(from: value)))
        default:
            throw Error.unimplemented(asn1)
        }
    }
}
