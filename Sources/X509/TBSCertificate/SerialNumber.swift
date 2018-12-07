import ASN1
import Stream

public struct SerialNumber: Equatable {
    public let bytes: [UInt8]
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1

extension SerialNumber {
    // CertificateSerialNumber  ::=  INTEGER
    public init(from asn1: ASN1) throws {
        guard let bytes = asn1.insaneIntegerValue,
            bytes.count > 0 else
        {
            throw X509.Error.invalidASN1(asn1, in: .serialNumber(.format))
        }
        self.bytes = bytes
    }
}

// MARK: Error

extension SerialNumber {
    public enum Error {
        public enum Origin {
            case format
        }
    }
}
