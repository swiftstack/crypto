import ASN1

extension Extension {
    public struct CertificateType: OptionSet, Equatable {
        public let padding: UInt8
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.padding = 0
            self.rawValue = rawValue
        }

        public init(padding: UInt8, rawValue: UInt8) {
            self.padding = padding
            self.rawValue = rawValue
        }

        public static let sslClient = CertificateType(rawValue: 1 << 7)
        public static let sslServer = CertificateType(rawValue: 1 << 6)
        public static let smime = CertificateType(rawValue: 1 << 5)
        public static let objectSigning = CertificateType(rawValue: 1 << 4)
        // public static let reserved = CertificateType(rawValue: 1 << 3)
        public static let sslCA = CertificateType(rawValue: 1 << 2)
        public static let smimeCA = CertificateType(rawValue: 1 << 1)
        public static let objectSigningCA = CertificateType(rawValue: 1 << 0)
    }
}

// MARK: Coding - https://

extension Extension.CertificateType {
    // CertificateType ::= BIT STRING   {
    //   sslClient               (0),
    //   sslServer               (1),
    //   smime                   (2),
    //   objectSigning           (3),
    //   reserved                (4),
    //   sslCA                   (5),
    //   smimeCA                 (6),
    //   objectSigningCA         (7)}
    public init(from asn1: ASN1) throws {
        guard asn1.tag == .bitString,
            let data = asn1.dataValue,
            data.count == 2 else
        {
            throw Error.invalidASN1(asn1)
        }
        self.padding = data[0]
        self.rawValue = data[1]
    }
}
