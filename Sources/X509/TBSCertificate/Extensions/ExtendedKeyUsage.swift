import ASN1

extension Extension {
    public struct ExtendedKeyUsage: Equatable {
        public typealias KeyPurpose = ASN1.ObjectIdentifier.Pkix.KeyPurpose

        public let keyPurposes: [KeyPurpose]
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.2.1.12

extension Extension.ExtendedKeyUsage {
    //  ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

    //  KeyPurposeId ::= OBJECT IDENTIFIER
    public init(from asn1: ASN1) throws {
        guard
            let sequence = asn1.sequenceValue,
            sequence.count > 0
        else {
            throw Error.invalidASN1(asn1)
        }
        self.keyPurposes = try sequence.map {
            guard let id = $0.objectIdentifierValue else {
                throw Error.invalidASN1(asn1)
            }
            switch id {
            case .pkix(.some(.keyPurpose(.serverAuth))): return .serverAuth
            case .pkix(.some(.keyPurpose(.clientAuth))): return .clientAuth
            default: return .other(id)
            }
        }
    }
}
