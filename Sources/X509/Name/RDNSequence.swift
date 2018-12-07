import ASN1

public struct RDNSequence: Equatable {
    public let items: [RelativeDistinguishedName]

    public init(_ items: [RelativeDistinguishedName]) {
        self.items = items
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.4

extension RDNSequence {
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue else {
            throw Error.invalidASN1(asn1)
        }
        self.items = try sequence.map { try .init(from: $0) }
    }
}
