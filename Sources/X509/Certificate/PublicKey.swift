import ASN1

extension Certificate {
    public enum PublicKey: Equatable {
        case rsa(modulus: [UInt8], exponent: Int)
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.7

extension Certificate.PublicKey {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2 else
        {
            throw X509.Error(.invalidPublicKey, asn1)
        }
        let algorithm = try Algorithm(from: sequence[0])
        guard algorithm == .rsaEncryption else {
            throw X509.Error(.unsupportedAlgorithm, asn1)
        }
        guard let bitString = BitString(from: sequence[1]) else {
            throw X509.Error(.invalidPublicKey, asn1)
        }
        let key = try ASN1(from: bitString.bytes)
        guard let keySequence = key.sequenceValue,
            keySequence.count == 2,
            let modulus = keySequence[0].insaneIntegerValue,
            let exponent = keySequence[1].integerValue else
        {
            throw X509.Error(.invalidPublicKey, asn1)
        }
        self = .rsa(modulus: modulus, exponent: exponent)
    }
}
