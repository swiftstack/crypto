import ASN1

public typealias RelativeDistinguishedName = Set<AttributeTypeAndValue>

// https://tools.ietf.org/html/rfc5280#section-4.1.2.4

extension Set where Element == AttributeTypeAndValue {
    // RelativeDistinguishedName ::=
    //   SET SIZE (1..MAX) OF AttributeTypeAndValue
    public init(from asn1: ASN1) throws {
        guard let items = asn1.setValue,
            items.count >= 1 else
        {
            throw X509.Error(.invalidRelativeDistinguishedName, asn1)
        }
        var name = RelativeDistinguishedName()
        for item in items {
            try name.insert(.init(from: item))
        }
        self = name
    }
}
