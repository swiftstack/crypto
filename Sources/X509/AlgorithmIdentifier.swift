import ASN1

// Generic structure used to encode context-specific algorithm groups
// such as Signature.Algorithm and PublicKey.Algorithm

public struct AlgorithmIdentifier: Equatable {
    public let objectId: ASN1.ObjectIdentifier
    public let parameters: [UInt8]?

    public init(objectId: ASN1.ObjectIdentifier, parameters: [UInt8]? = nil) {
        self.objectId = objectId
        self.parameters = parameters
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1.1.2

extension AlgorithmIdentifier {
    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //   algorithm               OBJECT IDENTIFIER,
    //   parameters              ANY DEFINED BY algorithm OPTIONAL  }
    //                              -- contains a value of the type
    //                              -- registered for use with the
    //                              -- algorithm object identifier value
    init(from asn1: ASN1) throws {
        guard
            let sequence = asn1.sequenceValue,
            sequence.count == 2,
            let objectId = sequence[0].objectIdentifierValue
        else {
            throw Error.invalidASN1(asn1)
        }
        self.objectId = objectId
        switch sequence[1].tag {
        case .null: self.parameters = nil
        default: self.parameters = sequence[1].dataValue
        }
    }
}
