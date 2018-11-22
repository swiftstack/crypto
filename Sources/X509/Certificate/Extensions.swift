import ASN1
import Stream

extension Certificate {
    public struct Extensions: Equatable {
        public var basicConstrains: BasicConstrains?
        public var cRLDistributionPoints: CRLDistributionPoints?

        public init(
            basicConstrains: BasicConstrains? = nil,
            cRLDistributionPoints: CRLDistributionPoints? = nil)
        {
            self.basicConstrains = basicConstrains
            self.cRLDistributionPoints = cRLDistributionPoints
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2

extension Certificate.Extensions {
    public init(from asn1: ASN1) throws {
        guard let contextSpecific = asn1.sequenceValue,
            let container = contextSpecific.first,
            let sequence = container.sequenceValue else
        {
            throw X509.Error(.invalidExtensions, asn1)
        }

        self.init()

        for item in sequence {
            guard let values = item.sequenceValue,
                let oid = values.first?.objectIdentifierValue,
                case .certificateExtension(let `extension`) = oid else
            {
                throw X509.Error(.invalidExtensions, asn1)
            }

            switch `extension` {
            case .basicConstrains:
                self.basicConstrains = try .init(from: item)
            case .crlDistributionPoints:
                self.cRLDistributionPoints = try .init(from: item)
            default:
                throw X509.Error(.unimplementedExtension, asn1)
            }
        }
    }
}
