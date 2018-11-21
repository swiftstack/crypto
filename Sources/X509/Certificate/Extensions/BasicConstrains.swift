import ASN1
import Stream

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
    typealias CertificateExtension = ASN1.Objects.CertificateExtension

    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            let objectId = sequence.first,
            objectId.tag == .objectIdentifier,
            let id = objectId.dataValue,
            id == CertificateExtension.basicConstrains,
            sequence.count == 3,
            let isCritical = sequence[1].booleanValue,
            let data = sequence[2].dataValue else
        {
            throw X509.Error.invalidExtension("BasicConstrains")
        }

        let asn1 = try ASN1(from: InputByteStream(data))
        guard let constrains = asn1.sequenceValue else {
            throw X509.Error.invalidExtension("BasicConstrains")
        }

        self.isCritical = isCritical

        // TODO: test
        guard constrains.count <= 2 else {
            throw X509.Error.invalidExtension("BasicConstrains")
        }

        // DEFAULT FALSE
        if constrains.count >= 1 {
            guard let isCA = constrains[1].booleanValue else {
                throw X509.Error.invalidExtension("BasicConstrains")
            }
            self.isCA = isCA
        } else {
            self.isCA = false
        }

        // OPTIONAL
        if constrains.count == 2 {
            guard let pathLen = constrains[2].integerValue else {
                throw X509.Error.invalidExtension("BasicConstrains")
            }
            self.pathLen = pathLen
        } else {
            self.pathLen = nil
        }
    }
}
