import ASN1
import Stream
import Time

extension Certificate {
    public struct Validity: Equatable {
        public let notBefore: Time
        public let notAfter: Time

        public init(notBefore: Time, notAfter: Time) {
            self.notBefore = notBefore
            self.notAfter = notAfter
        }
    }
}

extension Certificate.Validity {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2,
            sequence[0].tag == .utcTime,
            sequence[1].tag == .utcTime,
            let notBeforeBytes = sequence[0].dataValue,
            let notAfterBytes = sequence[1].dataValue,
            let notBefore = Time(validity: notBeforeBytes),
            let notAfter = Time(validity: notAfterBytes) else
        {
            throw X509.Error.invalidValidity
        }
        self.notBefore = notBefore
        self.notAfter = notAfter
    }
}

// MARK: Utils

extension Time {
    init?(validity: [UInt8]) {
        let string = String(decoding: validity, as: UTF8.self)
        self.init(string, format: "%d%m%y%H%M%S")
    }
}
