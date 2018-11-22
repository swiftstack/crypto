import ASN1

extension Certificate.Extensions {
    public struct BasicConstrains: Equatable {
        public let isCritical: Bool
        public let isCA: Bool
        public let pathLen: Int?

        public init(
            isCritical: Bool,
            isCA: Bool = false,
            pathLen: Int? = nil)
        {
            self.isCritical = isCritical
            self.isCA = isCA
            self.pathLen = pathLen
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9

extension Certificate.Extensions.BasicConstrains {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            let oid = sequence.first?.objectIdentifierValue,
            oid == .certificateExtension(.basicConstrains),
            sequence.count == 3,
            let isCritical = sequence[1].booleanValue,
            let data = sequence[2].dataValue else
        {
            throw X509.Error(.invalidExtension, asn1)
        }

        let asn1 = try ASN1(from: data)
        guard let constrains = asn1.sequenceValue else {
            throw X509.Error(.invalidExtension, asn1)
        }

        self.isCritical = isCritical

        // TODO: test
        guard constrains.count <= 2 else {
            throw X509.Error(.invalidExtension, asn1)
        }

        // DEFAULT FALSE
        if constrains.count >= 1 {
            guard let isCA = constrains[0].booleanValue else {
                throw X509.Error(.invalidExtension, asn1)
            }
            self.isCA = isCA
        } else {
            self.isCA = false
        }

        // OPTIONAL
        if constrains.count == 2 {
            guard let pathLen = constrains[1].integerValue else {
                throw X509.Error(.invalidExtension, asn1)
            }
            self.pathLen = pathLen
        } else {
            self.pathLen = nil
        }
    }
}
