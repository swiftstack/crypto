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
            throw Error.invalidASN1(asn1, origin: .header)
        }
        self.type = type
        self.value = sequence[1]
    }
}

// MARK: Error

extension AttributeTypeAndValue {
    public enum Error {
        public enum Origin {
            case header
        }

        static func invalidASN1(_ asn1: ASN1, origin: Origin) -> X509.Error {
            return .init(
                .invalidASN1,
                in: .attributeTypeAndValue(origin),
                data: asn1)
        }
    }
}
