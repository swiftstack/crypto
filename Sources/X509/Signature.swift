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
        fatalError()
    }
}

extension Signature.Algorithm {
    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //   algorithm               OBJECT IDENTIFIER,
    //   parameters              ANY DEFINED BY algorithm OPTIONAL  }
    //                              -- contains a value of the type
    //                              -- registered for use with the
    //                              -- algorithm object identifier value
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count >= 2,
            let value = sequence.first,
            let oid = value.objectIdentifierValue else
        {
            throw X509.Error.invalidASN1(asn1, in: .signature(.algorithm))
        }
        switch oid {
        // TODO: move to public key
        // case .rsaEncryption:
        //     self = .rsa
        case .sha256WithRSAEncryption:
            self = .sha256WithRSA
        default:
            throw X509.Error.unimplemented(.signature(.algorithm), data: asn1)
        }
        // TODO: imlement parameters
        let parameters = sequence[1]
        guard parameters.tag == .null else {
            throw X509.Error.unimplemented(.signature(.parameters), data: asn1)
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1.3

extension Signature.Value {
    public init(from asn1: ASN1) throws {
        guard let bitString = BitString(from: asn1) else {
            throw X509.Error.invalidASN1(asn1, in: .signature(.value))
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

// MARK: Error

extension Signature {
    public enum Error {
        public enum Origin {
            case algorithm
            case parameters
            case value
        }
    }
}
