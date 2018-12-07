import ASN1
import Stream
import Time

public typealias SwiftCoreTime = Time

extension TBSCertificate {
    public enum Time: Equatable {
        case utc(SwiftCoreTime)
        case generalized(SwiftCoreTime)
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.1

extension TBSCertificate.Time {
    // Time ::= CHOICE {
    //   utcTime        UTCTime,
    //   generalTime    GeneralizedTime }
    public init(from asn1: ASN1) throws {
        guard let bytes = asn1.dataValue,
            let time = Time(validity: bytes) else
        {
            throw X509.Error(.invalidTime, asn1)
        }
        switch asn1.tag {
            case .utcTime: self = .utc(time)
            case .generalizedTime: self = .generalized(time)
            default: throw X509.Error(.invalidTime, asn1)
        }
    }
}

// MARK: Utils

extension Time {
    init?(validity: [UInt8]) {
        let string = String(decoding: validity, as: UTF8.self)
        self.init(string, format: "%d%m%y%H%M%S")
    }
}
