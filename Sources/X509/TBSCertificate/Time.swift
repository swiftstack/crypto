import ASN1
import Time
import Stream

public enum TimeVariant: Equatable {
    case utc(Time)
    case generalized(Time)
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1

extension TimeVariant {
    // Time ::= CHOICE {
    //   utcTime        UTCTime,
    //   generalTime    GeneralizedTime }
    public init(from asn1: ASN1) throws {
        guard
            let bytes = asn1.dataValue,
            let time = Time(validity: bytes)
        else {
            throw Error.invalidASN1(asn1)
        }
        switch asn1.tag {
        case .utcTime: self = .utc(time)
        case .generalizedTime: self = .generalized(time)
        default: throw Error.invalidASN1(asn1)
        }
    }
}

// MARK: Utils

private extension Time {
    init?(validity: [UInt8]) {
        let string = String(decoding: validity, as: UTF8.self)
        self.init(string, format: "%d%m%y%H%M%S")
    }
}
