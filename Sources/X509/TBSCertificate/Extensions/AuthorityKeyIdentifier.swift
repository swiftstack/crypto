import ASN1

extension Extension {
    public struct AuthorityKeyIdentifier: Equatable {
        public var keyIdentifier: KeyIdentifier?
        public var authorityCertIssuer: GeneralNames?
        public var authorityCertSerialNumber: SerialNumber?

        public init(
            keyIdentifier: KeyIdentifier? = nil,
            authorityCertIssuer: GeneralNames? = nil,
            authorityCertSerialNumber: SerialNumber? = nil)
        {
            self.keyIdentifier = keyIdentifier
            self.authorityCertIssuer = authorityCertIssuer
            self.authorityCertSerialNumber = authorityCertSerialNumber
        }
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.2.1.9

extension Extension.AuthorityKeyIdentifier {
    // AuthorityKeyIdentifier ::= SEQUENCE {
    //   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    //   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    //   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count <= 3 else
        {
            throw X509.Error.invalidASN1(asn1, in: .authorityKeyIdentifier(.rootSequence))
        }
        self.init()
        for item in sequence {
            switch item.tag.rawValue {
            case 0: self.keyIdentifier = try .init(from: item)
            case 1: self.authorityCertIssuer = try .init(from: item)
            case 2: self.authorityCertSerialNumber = try .init(from: item)
            default: throw X509.Error.invalidASN1(item, in: .authorityKeyIdentifier(.tag))
            }
        }
    }
}

// MARK: Error

extension Extension.AuthorityKeyIdentifier {
    public enum Error {
        public enum Origin {
            case rootSequence
            case tag
        }
    }
}
