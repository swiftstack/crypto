import ASN1
import Stream

extension TBSCertificate {
    public struct Validity: Equatable {
        public let notBefore: Time
        public let notAfter: Time

        public init(notBefore: Time, notAfter: Time) {
            self.notBefore = notBefore
            self.notAfter = notAfter
        }
    }
}

extension TBSCertificate.Validity {
    // Validity ::= SEQUENCE {
    //   notBefore      Time,
    //   notAfter       Time }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2 else
        {
            throw X509.Error(.invalidValidity, asn1)
        }
        self.notBefore = try TBSCertificate.Time(from: sequence[0])
        self.notAfter = try TBSCertificate.Time(from: sequence[1])
    }
}
