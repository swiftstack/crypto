import ASN1
import Stream

public enum TimeVariant: Equatable {
    case utc(String)
    case generalized(String)
}

// MARK: Coding - https://tools.ietf.org/html/rfc5280#section-4.1

extension TimeVariant {
    // Time ::= CHOICE {
    //   utcTime        UTCTime,
    //   generalTime    GeneralizedTime }
    public init(from asn1: ASN1) throws {
        guard
            let bytes = asn1.dataValue
        else {
            throw Error.invalidASN1(asn1)
        }
        let time = String(decoding: bytes, as: UTF8.self)
        switch asn1.tag {
        case .utcTime: self = .utc(time)
        case .generalizedTime: self = .generalized(time)
        default: throw Error.invalidASN1(asn1)
        }
    }
}
