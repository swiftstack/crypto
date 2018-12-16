import ASN1
import Stream

public struct SerialNumber: Equatable {
    public let value: ASN1.Integer
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1

extension SerialNumber {
    // CertificateSerialNumber  ::=  INTEGER
    public init(from asn1: ASN1) throws {
        guard case .integer(let value) = asn1.content else {
            throw Error.invalidASN1(asn1)
        }
        self.value = value
    }
}
