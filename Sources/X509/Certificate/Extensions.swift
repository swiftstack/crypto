import ASN1
import Stream

extension Certificate {
    public struct Extensions: Equatable {
        public var basicConstrains: BasicConstrains?

        public init(basicConstrains: BasicConstrains? = nil) {
            self.basicConstrains = basicConstrains
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2

extension Certificate.Extensions {
    typealias CertificateExtension = ASN1.Objects.CertificateExtension

    public init(from asn1: ASN1) throws {
        guard let contextSpecific = asn1.sequenceValue,
            let container = contextSpecific.first,
            let sequence = container.sequenceValue else
        {
            throw X509.Error.invalidExtensions
        }

        self.init()

        for item in sequence {
            guard let values = item.sequenceValue,
                let objectId = values.first,
                objectId.tag == .objectIdentifier,
                let id = objectId.dataValue else
            {
                throw X509.Error.invalidExtensions
            }

            switch id {
            case CertificateExtension.basicConstrains:
                self.basicConstrains = try .init(from: item)
            default:
                throw X509.Error.unimplementedExtension(String(oid: id))
            }
        }
    }
}
