import ASN1

public enum Name: Equatable {
    case rdnSequence(RDNSequence)
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.4

extension Name {
    // Name ::= CHOICE { -- only one possibility for now --
    //   rdnSequence  RDNSequence }
    public init(from asn1: ASN1) throws {
        guard asn1.tag == .sequence else {
            throw X509.Error(.invalidDistinguishedName, asn1)
        }
        self = .rdnSequence(try RDNSequence(from: asn1))
    }
}
