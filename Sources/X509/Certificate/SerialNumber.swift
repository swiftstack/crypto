import ASN1
import Stream

extension Certificate {
    public struct SerialNumber: Equatable {
        public let bytes: [UInt8]
    }
}

extension Certificate.SerialNumber {
    public init(from asn1: ASN1) throws {
        guard let bytes = asn1.insaneIntegerValue,
            bytes.count > 0 else
        {
            throw X509.Error.invalidSerialNumber
        }
        self.bytes = bytes
    }
}
