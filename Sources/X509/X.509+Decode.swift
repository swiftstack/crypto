import ASN1
import Time
import Stream

// https://tools.ietf.org/html/rfc5280

extension X509 {
    public enum Error: Swift.Error {
        case invalidX509
        case invalidCertificate
        case invalidAlgorithm
        case unimplementedAlgorithm(String)
        case invalidSignature
        case invalidVersion
        case invalidSerialNumber
        case invalidIdentifier
        case unimplementedIdentifierValue(String)
        case invalidValidity
        case unsupportedAlgorithm
        case invalidPublicKey
        case invalidExtensions
        case unimplementedExtension(String)
        case invalidExtensionBasicConstrain
    }

    public init(from asn1: ASN1) throws {
        guard asn1.isConstructed,
            let sequence = asn1.sequenceValue,
            sequence.count == 3
        else {
            throw Error.invalidX509
        }

        self.certificate = try Certificate(from: sequence[0])
        self.algorithm = try Algorithm(from: sequence[1])
        self.signature = try Signature(from: sequence[2])
    }
}

extension Certificate {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count >= 8 else
        {
            throw X509.Error.invalidSignature
        }

        self.version = try Version(from: sequence[0])
        self.serialNumber = try SerialNumber(from: sequence[1])
        self.algorithm = try Algorithm(from: sequence[2])
        self.issuer = try Identifier(from: sequence[3])
        self.validity = try Validity(from: sequence[4])
        self.subject = try Identifier(from: sequence[5])
        self.publicKey = try PublicKey(from: sequence[6])
        self.extensions = try Extensions(from: sequence[7])
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

extension Certificate.SerialNumber {
    public init(from asn1: ASN1) throws {
        guard let bytes = asn1.insaneIntegerValue,
            bytes.count > 0 else
        {
            throw X509.Error.invalidSerialNumber
        }
        self.bytes = bytes
    }
}

extension Certificate.Identifier {
    typealias OID = ASN1.Objects

    public init(from asn1: ASN1) throws {
        var nameRequired: String? = nil
        var countryRequired: String? = nil
        var organizationRequired: String? = nil
        var organizationalUnit: String? = nil
        var locality: String? = nil
        var stateOrProvince: String? = nil

        guard let sequence = asn1.sequenceValue else {
            throw X509.Error.invalidIdentifier
        }

        for item in sequence {
            guard
                item.tag == .set,
                let set = item.sequenceValue,
                set.count == 1,
                let sequence = set[0].sequenceValue,
                sequence.count == 2,
                sequence[0].tag == .objectIdentifier,
                let id = sequence[0].dataValue,
                let value = sequence[1].stringValue else
            {
                throw X509.Error.invalidIdentifier
            }
            switch id {
            case OID.countryName:
                countryRequired = value
            case OID.organizationName:
                organizationRequired = value
            case OID.organizationalUnitName:
                organizationalUnit = value
            case OID.localityName:
                locality = value
            case OID.stateOrProvinceName:
                stateOrProvince = value
            case OID.commonName:
                nameRequired = value
            default:
                throw X509.Error.unimplementedIdentifierValue(String(oid: id))
            }
        }

        guard let country = countryRequired,
            let organization = organizationRequired,
            let name = nameRequired else
        {
            throw X509.Error.invalidIdentifier
        }

        self.country = country
        self.organization = organization
        self.organizationalUnit = organizationalUnit
        self.locality = locality
        self.stateOrProvince = stateOrProvince
        self.name = name
    }
}

extension Certificate.Validity {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2,
            sequence[0].tag == .utcTime,
            sequence[1].tag == .utcTime,
            let notBeforeBytes = sequence[0].dataValue,
            let notAfterBytes = sequence[1].dataValue,
            let notBefore = Time(validity: notBeforeBytes),
            let notAfter = Time(validity: notAfterBytes) else
        {
            throw X509.Error.invalidValidity
        }
        self.notBefore = notBefore
        self.notAfter = notAfter
    }
}

extension Certificate.PublicKey {
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2 else
        {
            throw X509.Error.invalidPublicKey
        }
        let algorithm = try Algorithm(from: sequence[0])
        guard algorithm == .rsaEncryption else {
            throw X509.Error.unsupportedAlgorithm
        }
        guard let bitString = BitString(from: sequence[1]) else {
            throw X509.Error.invalidPublicKey
        }
        let key = try ASN1(from: InputByteStream(bitString.bytes))
        guard let keySequence = key.sequenceValue,
            keySequence.count == 2,
            let modulus = keySequence[0].insaneIntegerValue,
            let exponent = keySequence[1].integerValue else
        {
            throw X509.Error.invalidPublicKey
        }
        self = .rsa(modulus: modulus, exponent: exponent)
    }
}

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

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9

extension Certificate.Extensions.BasicConstrains {
    typealias CertificateExtension = ASN1.Objects.CertificateExtension

    public init(from asn1: ASN1) throws {
        guard
            // object id
            let values = asn1.sequenceValue,
            let objectId = values.first,
            objectId.tag == .objectIdentifier,
            let id = objectId.dataValue,
            id == CertificateExtension.basicConstrains,
            values.count == 3,
            // NOTE: isCritical?
            let isCritical = values[1].booleanValue,
            let data = values[2].dataValue else
        {
            throw X509.Error.invalidExtensionBasicConstrain
        }

        let asn1 = try ASN1(from: InputByteStream(data))
        guard let constrains = asn1.sequenceValue else {
            throw X509.Error.invalidExtensionBasicConstrain
        }

        self.isCritical = isCritical

        // TODO: test
        guard constrains.count <= 2 else {
            throw X509.Error.invalidExtensionBasicConstrain
        }

        // BOOLEAN DEFAULT FALSE
        if constrains.count >= 1 {
            guard let isCA = constrains[1].booleanValue else {
                throw X509.Error.invalidExtensionBasicConstrain
            }
            self.isCA = isCA
        } else {
            self.isCA = false
        }

        // INTEGER (0..MAX) OPTIONAL
        if constrains.count == 2 {
            guard let pathLen = constrains[2].integerValue else {
                throw X509.Error.invalidExtensionBasicConstrain
            }
            self.pathLen = pathLen
        } else {
            self.pathLen = nil
        }
    }
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

extension Signature {
    public init(from asn1: ASN1) throws {
        guard let bitString = BitString(from: asn1) else {
            throw X509.Error.invalidSignature
        }
        self.padding = bitString.padding
        self.encrypted = bitString.bytes
    }
}

// MARK: Utils

extension Time {
    init?(validity: [UInt8]) {
        let string = String(decoding: validity, as: UTF8.self)
        self.init(string, format: "%d%m%y%H%M%S")
    }
}

struct BitString {
    let padding: Int
    let bytes: [UInt8]

    init?(from asn1: ASN1) {
        guard asn1.tag == .bitString,
            let data = asn1.dataValue,
            data.count >= 2 else
        {
            return nil
        }
        self.padding = Int(data[0])
        self.bytes = [UInt8](data[1...])
    }
}
