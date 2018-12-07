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
            throw Error.invalidASN1(asn1, in: .format)
        }
        self = .rdnSequence(try RDNSequence(from: asn1))
    }
}

// MARK: Error

extension Name {
    public enum Error {
        public enum Origin {
            case format
        }

        static func invalidASN1(_ asn1: ASN1, in origin: Origin) -> X509.Error {
            return .init(
                .invalidASN1,
                in: .distinguishedName(origin),
                data: asn1)
        }
    }
}
