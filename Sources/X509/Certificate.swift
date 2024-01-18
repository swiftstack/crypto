import ASN1

public struct Certificate: Equatable {
    public let tbsCertificate: TBSCertificate
    public let signature: Signature

    public init(
        tbsCertificate: TBSCertificate,
        signature: Signature
    ) {
        self.tbsCertificate = tbsCertificate
        self.signature = signature
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1

extension Certificate {
    // Certificate  ::=  SEQUENCE  {
    //   tbsCertificate       TBSCertificate,
    //   signatureAlgorithm   AlgorithmIdentifier,
    //   signatureValue       BIT STRING  }
    public static func decode(from asn1: ASN1) async throws -> Self {
        guard asn1.isConstructed,
            let sequence = asn1.sequenceValue,
            sequence.count == 3
        else {
            throw Error.invalidASN1(asn1)
        }
        let tbsCertificate = try await TBSCertificate.decode(from: sequence[0])
        let signature = try Signature(
            algorithm: .init(from: sequence[1]),
            value: .init(from: sequence[2]))
        return .init(tbsCertificate: tbsCertificate, signature: signature)
    }

    public func encode() -> ASN1 {
        fatalError("unimplemented")
    }
}
