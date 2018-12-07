import ASN1
import Time
import Stream

// https://tools.ietf.org/html/rfc5280

public struct Certificate: Equatable {
    public let tbsCertificate: TBSCertificate
    public let algorithm: Algorithm
    public let signature: Signature

    public init(
        tbsCertificate: TBSCertificate,
        algorithm: Algorithm,
        signature: Signature)
    {
        self.tbsCertificate = tbsCertificate
        self.algorithm = algorithm
        self.signature = signature
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.1

extension Certificate {
    public init(from asn1: ASN1) throws {
        guard asn1.isConstructed,
            let sequence = asn1.sequenceValue,
            sequence.count == 3
        else {
            throw Error(.invalidX509, asn1)
        }
        self.tbsCertificate = try TBSCertificate(from: sequence[0])
        self.algorithm = try Algorithm(from: sequence[1])
        self.signature = try Signature(from: sequence[2])
    }
}
