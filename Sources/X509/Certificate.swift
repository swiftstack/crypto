import ASN1
import Stream

public struct Certificate: Equatable {
    public let version: Version
    public let serialNumber: SerialNumber
    public let algorithm: Algorithm
    public let issuer: Identifier
    public let validity: Validity
    public let subject: Identifier
    public let publicKey: PublicKey
    public let extensions: Extensions

    public init(
        version: Version,
        serialNumber: SerialNumber,
        algorithm: Algorithm,
        issuer: Identifier,
        validity: Validity,
        subject: Identifier,
        publicKey: PublicKey,
        extensions: Extensions)
    {
        self.version = version
        self.serialNumber = serialNumber
        self.algorithm = algorithm
        self.issuer = issuer
        self.validity = validity
        self.subject = subject
        self.publicKey = publicKey
        self.extensions = extensions
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.1

extension Certificate {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count >= 8 else
        {
            throw X509.Error.invalidSignature
        }

        self.version = try Version(from: sequence[0])
        self.serialNumber = try SerialNumber(from: sequence[1])
        self.algorithm = try Algorithm(from: sequence[2])
        self.issuer = try Identifier(from: sequence[3])
        self.validity = try Validity(from: sequence[4])
        self.subject = try Identifier(from: sequence[5])
        self.publicKey = try PublicKey(from: sequence[6])
        self.extensions = try Extensions(from: sequence[7])
    }
}
