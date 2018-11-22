import ASN1

public struct AttributeTypeAndValue: Hashable {
    public let type: ASN1.ObjectIdentifier
    public let value: ASN1

    public var hashValue: Int {
        return type.hashValue
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.4

extension AttributeTypeAndValue {
    // AttributeTypeAndValue ::= SEQUENCE {
    //   type     AttributeType,
    //   value    AttributeValue }
    //
    // AttributeType ::= OBJECT IDENTIFIER
    //
    // AttributeValue ::= ANY -- DEFINED BY AttributeType
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2,
            let type = sequence[0].objectIdentifierValue else
        {
            throw X509.Error(.invalidAttributeTypeAndValue, asn1)
        }
        self.type = type
        self.value = sequence[1]
    }
}
