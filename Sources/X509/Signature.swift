import ASN1

public struct Signature: Equatable {
    public let algorithm: Algorithm
    public let value: Value

    public enum Algorithm: Equatable {
        case md2WithRSA
        case md5WithRSA
        case sha1WithRSA
        case sha256WithRSA
        case sha384WithRSA
        case sha512WithRSA
        case dsaWithSHA1
        case dsaWithSHA256
        case ecdsaAWithSHA1
        case ecdsaWithSHA256
        case ecdsaWithSHA384
        case ecdsaWithSHA512
        case sha256WithRSAPSS
        case sha384WithRSAPSS
        case sha512WithRSAPSS
    }

    public struct Value: Equatable {
        public let padding: Int
        public let encrypted: [UInt8]

        public init(padding: Int, encrypted: [UInt8]) {
            self.padding = padding
            self.encrypted = encrypted
        }
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1.1.2

extension Signature {
    public init(from asn1: ASN1) throws {
        fatalError("unimplemented")
    }
}

extension Signature.Algorithm {
    public init(from asn1: ASN1) throws {
        let algorithmIdentifier = try AlgorithmIdentifier(from: asn1)
        // TODO: Use enum Signature with payload
        switch algorithmIdentifier.objectId {
        case .sha256WithRSAEncryption:
            self = .sha256WithRSA
        default:
            throw Error.unimplemented(asn1)
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1.3

extension Signature.Value {
    public init(from asn1: ASN1) throws {
        guard let bitString = BitString(from: asn1) else {
            throw Error.invalidASN1(asn1)
        }
        self.padding = bitString.padding
        self.encrypted = bitString.bytes
    }
}

struct BitString {
    let padding: Int
    let bytes: [UInt8]

    init?(from asn1: ASN1) {
        guard asn1.tag == .bitString,
            let data = asn1.dataValue,
            // FIXME: probably invalid
            data.count >= 2 else
        {
            return nil
        }
        self.padding = Int(data[0])
        self.bytes = [UInt8](data[1...])
    }
}
