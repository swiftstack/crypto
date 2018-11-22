import ASN1
import Stream

public enum Algorithm {
    case sha256WithRSAEncryption
    case rsaEncryption
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1.2

extension Algorithm {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count >= 2,
            let value = sequence.first,
            let oid = value.objectIdentifierValue else
        {
            throw X509.Error.invalidSignature
        }
        switch oid {
        case .rsaEncryption:
            self = .rsaEncryption
        case .sha256WithRSAEncryption:
            self = .sha256WithRSAEncryption
        default:
            throw X509.Error.unimplementedAlgorithm(oid.stringValue)
        }
        // TODO: imlement parameters
        let parameters = sequence[1]
        guard parameters.tag == .null else {
            throw X509.Error.invalidSignature
        }
    }
}
