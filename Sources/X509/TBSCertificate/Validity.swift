import ASN1
import Time

public struct Validity: Equatable {
    public let notBefore: TimeVariant
    public let notAfter: TimeVariant

    public init(notBefore: TimeVariant, notAfter: TimeVariant) {
        self.notBefore = notBefore
        self.notAfter = notAfter
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1.2.5

extension Validity {
    // Validity ::= SEQUENCE {
    //   notBefore      Time,
    //   notAfter       Time }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2 else
        {
            throw X509.Error.invalidASN1(asn1, in: .validity(.format))
        }
        self.notBefore = try TimeVariant(from: sequence[0])
        self.notAfter = try TimeVariant(from: sequence[1])
    }
}

// MARK: Error

extension Validity {
    public enum Error {
        public enum Origin {
            case format
        }
    }
}
