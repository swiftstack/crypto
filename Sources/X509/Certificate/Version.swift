import ASN1
import Stream

extension Certificate {
    public enum Version: UInt8, Equatable {
        case v3 = 0x02
    }
}

extension Certificate.Version {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 1,
            let value = sequence[0].integerValue,
            let rawVersion = UInt8(exactly: value),
            let version = Certificate.Version(rawValue: rawVersion) else
        {
            throw X509.Error.invalidVersion
        }
        self = version
    }
}
