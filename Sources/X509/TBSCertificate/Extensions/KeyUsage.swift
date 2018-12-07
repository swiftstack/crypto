import ASN1

extension Extension {
    public struct KeyUsage: OptionSet, Equatable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        public static let digitalSignature = KeyUsage(rawValue: 1 << 15)
        public static let nonRepudiation = KeyUsage(rawValue: 1 << 14)
        public static let keyEncipherment = KeyUsage(rawValue: 1 << 13)
        public static let dataEncipherment = KeyUsage(rawValue: 1 << 12)
        public static let keyAgreement = KeyUsage(rawValue: 1 << 11)
        public static let keyCertSign = KeyUsage(rawValue: 1 << 10)
        public static let crlSign = KeyUsage(rawValue: 1 << 9)
        public static let encipherOnly = KeyUsage(rawValue: 1 << 8)
        public static let decipherOnly = KeyUsage(rawValue: 1 << 7)
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.2.1.3

extension Extension.KeyUsage {
    // KeyUsage ::= BIT STRING {
    //   digitalSignature        (0),
    //   nonRepudiation          (1), -- recent editions of X.509 have
    //                        -- renamed this bit to contentCommitment
    //   keyEncipherment         (2),
    //   dataEncipherment        (3),
    //   keyAgreement            (4),
    //   keyCertSign             (5),
    //   cRLSign                 (6),
    //   encipherOnly            (7),
    //   decipherOnly            (8) }
    public init(from asn1: ASN1) throws {
        guard asn1.tag == .bitString,
            let data = asn1.dataValue,
            data.count == 2 else
        {
            throw X509.Error.invalidASN1(asn1, in: .keyUsage(.format))
        }
        self.rawValue = UInt16(data[1]) << 8 | UInt16(data[0])
    }
}

// MARK: Error

extension Extension.KeyUsage {
    public enum Error {
        public enum Origin {
            case format
        }
    }
}
