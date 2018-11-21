import ASN1
import Stream

public enum Algorithm {
    case sha256WithRSAEncryption
    case rsaEncryption
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1.2

extension Algorithm {
    typealias OID = ASN1.Objects

    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count >= 2,
            let object = sequence.first,
            object.tag == .objectIdentifier,
            let id = object.dataValue else
        {
            throw X509.Error.invalidSignature
        }
        switch id {
        case OID.rsaEncryption:
            self = .rsaEncryption
        case OID.sha256WithRSAEncryption:
            self = .sha256WithRSAEncryption
        default:
            throw X509.Error.unimplementedAlgorithm(String(oid: id))
        }
        // TODO: imlement parameters
        let parameters = sequence[1]
        guard parameters.tag == .null else {
            throw X509.Error.invalidSignature
        }
    }
}
