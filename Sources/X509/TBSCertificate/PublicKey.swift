import ASN1

public struct RSA {
    public struct PublicKey: Equatable {
        public let modulus: [UInt8]
        public let exponent: Int
    }
}

public struct DSA { public struct PublicKey: Equatable {} }
public struct ECDSA { public struct PublicKey: Equatable {} }

public enum PublicKey: Equatable {
    case rsa(RSA.PublicKey)
    case dsa(DSA.PublicKey)
    case ecdsa(ECDSA.PublicKey)
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1.2.7

extension RSA.PublicKey {
    public init(from asn1: ASN1) throws {
        guard let keySequence = asn1.sequenceValue,
            keySequence.count == 2,
            let modulus = keySequence[0].insaneIntegerValue,
            let exponent = keySequence[1].integerValue else
        {
            throw X509.Error.invalidASN1(asn1, in: .publicKey(.value))
        }
        self.modulus = modulus
        self.exponent = exponent
    }
}

extension PublicKey {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2 else
        {
            throw X509.Error.invalidASN1(asn1, in: .publicKey(.format))
        }
        let algorithm = try Signature.Algorithm(from: sequence[0])
        guard let bitString = BitString(from: sequence[1]) else {
            throw X509.Error.invalidASN1(asn1, in: .publicKey(.bitString))
        }
        let key = try ASN1(from: bitString.bytes)
        self = .rsa(try .init(from: key))
    }
}

// MARK: Error

extension PublicKey {
    public enum Error {
        public enum Origin {
            case format
            case bitString
            case value
        }
    }
}
