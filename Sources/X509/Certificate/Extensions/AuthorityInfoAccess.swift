import ASN1

extension Certificate.Extension {
    public typealias AuthorityInfoAccess = [AccessDescription]

    public struct AccessDescription: Equatable {
        public var method: ASN1.ObjectIdentifier
        public var location: GeneralName

        public init(
            method: ASN1.ObjectIdentifier,
            location: GeneralName)
        {
            self.method = method
            self.location = location
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.2.1

extension Array where Element == Certificate.Extension.AccessDescription {
    public init(from asn1: ASN1) throws {
        // AuthorityInfoAccessSyntax  ::=
        //  SEQUENCE SIZE (1..MAX) OF AccessDescription
        guard let sequence = asn1.sequenceValue,
            sequence.count > 0 else
        {
            throw X509.Error(.invalidAuthorityInfoAccess, asn1)
        }
        self = try sequence.map(Certificate.Extension.AccessDescription.init)
    }
}

extension Certificate.Extension.AccessDescription {
    // AccessDescription  ::=  SEQUENCE {
    //   accessMethod          OBJECT IDENTIFIER,
    //   accessLocation        GeneralName  }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2,
            let method = sequence[0].objectIdentifierValue else
        {
            throw X509.Error(.invalidAccessDescription, asn1)
        }
        self.method = method
        self.location = try .init(from: sequence[1])
    }
}
