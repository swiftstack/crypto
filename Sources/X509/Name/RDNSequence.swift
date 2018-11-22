import ASN1

public typealias RDNSequence = [RelativeDistinguishedName]

// https://tools.ietf.org/html/rfc5280#section-4.1.2.4

extension Array where Element == RelativeDistinguishedName {
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue else {
            throw X509.Error(.invalidRDNSequence, asn1)
        }
        self = try sequence.map { try .init(from: $0) }
    }
}
