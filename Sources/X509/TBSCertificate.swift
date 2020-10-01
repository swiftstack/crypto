import ASN1

public struct TBSCertificate: Equatable {
    public let version: Version
    public let serialNumber: SerialNumber
    public let signature: Signature.Algorithm
    public let issuer: Name
    public let validity: Validity
    public let subject: Name
    public let publicKey: PublicKey
    public let extensions: Extensions

    public init(
        version: Version,
        serialNumber: SerialNumber,
        signature: Signature.Algorithm,
        issuer: Name,
        validity: Validity,
        subject: Name,
        publicKey: PublicKey,
        extensions: Extensions)
    {
        self.version = version
        self.serialNumber = serialNumber
        self.signature = signature
        self.issuer = issuer
        self.validity = validity
        self.subject = subject
        self.publicKey = publicKey
        self.extensions = extensions
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1

extension TBSCertificate {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count >= 8 else
        {
            throw Error.invalidASN1(asn1)
        }

        self.version = try Version(from: sequence[0])
        self.serialNumber = try SerialNumber(from: sequence[1])
        self.signature = try Signature.Algorithm(from: sequence[2])
        self.issuer = try Name(from: sequence[3])
        self.validity = try Validity(from: sequence[4])
        self.subject = try Name(from: sequence[5])
        self.publicKey = try PublicKey(from: sequence[6])
        self.extensions = try Extensions(from: sequence[7])
    }
}
