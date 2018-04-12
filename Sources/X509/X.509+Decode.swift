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
        guard asn1.identifier.isConstructed,
            case .sequence(let sequence) = asn1.content,
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
        guard case .sequence(let sequence) = asn1.content,
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
        guard case .sequence(let sequence) = asn1.content,
            sequence.count == 1,
            case .integer(.sane(let value)) = sequence[0].content,
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
        guard case .integer(.insane(let bytes)) = asn1.content,
            bytes.count > 0 else
        {
            throw X509.Error.invalidSerialNumber
        }
        self.bytes = bytes
    }
}

extension Certificate.Identifier {
    public init(from asn1: ASN1) throws {
        var nameRequired: String? = nil
        var countryRequired: String? = nil
        var organizationRequired: String? = nil
        var organizationalUnit: String? = nil
        var locality: String? = nil
        var stateOrProvince: String? = nil

        guard case .sequence(let sequence) = asn1.content else {
            throw X509.Error.invalidIdentifier
        }

        for item in sequence {
            guard
                item.identifier.tag == .set,
                case .sequence(let set) = item.content,
                set.count == 1,
                case .sequence(let sequence) = set[0].content,
                sequence.count == 2,
                sequence[0].identifier.tag == .objectIdentifier,
                case .data(let id) = sequence[0].content,
                case .string(let value) = sequence[1].content else
            {
                throw X509.Error.invalidIdentifier
            }
            switch id {
            case ASN1.Objects.countryName:
                countryRequired = value
            case ASN1.Objects.organizationName:
                organizationRequired = value
            case ASN1.Objects.organizationalUnitName:
                organizationalUnit = value
            case ASN1.Objects.localityName:
                locality = value
            case ASN1.Objects.stateOrProvinceName:
                stateOrProvince = value
            case ASN1.Objects.commonName:
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
        guard case .sequence(let sequence) = asn1.content,
            sequence.count == 2,
            sequence[0].identifier.tag == .utcTime,
            sequence[1].identifier.tag == .utcTime,
            case .data(let notBeforeBytes) = sequence[0].content,
            case .data(let notAfterBytes) = sequence[1].content,
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
        guard case .sequence(let sequence) = asn1.content,
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
        guard case .sequence(let keySequence) = key.content,
            keySequence.count == 2,
            case .integer(.insane(let modulus)) = keySequence[0].content,
            case .integer(.sane(let exponent)) = keySequence[1].content else
        {
            throw X509.Error.invalidPublicKey
        }
        self = .rsa(modulus: modulus, exponent: exponent)
    }
}

extension Certificate.Extensions {
    typealias CertificateExtension = ASN1.Objects.CertificateExtension

    public init(from asn1: ASN1) throws {
        guard case .sequence(let contextSpecific) = asn1.content,
            let container = contextSpecific.first,
            case .sequence(let sequence) = container.content else
        {
            throw X509.Error.invalidExtensions
        }

        self.basicConstrains = nil

        for item in sequence {
            guard case .sequence(let values) = item.content,
                let objectId = values.first,
                objectId.identifier.tag == .objectIdentifier,
                case .data(let id) = objectId.content else
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
    public init(from asn1: ASN1) throws {
        guard
            // object id
            case .sequence(let values) = asn1.content,
            let objectId = values.first,
            objectId.identifier.tag == .objectIdentifier,
            case .data(let id) = objectId.content,
            id == ASN1.Objects.CertificateExtension.basicConstrains,
            values.count == 3,
            // isCritical (?)
            case .boolean(let isCritical) = values[1].content,
            // BasicConstraints (?)
            case .data(let octetString) = values[2].content else
        {
            throw X509.Error.invalidExtensionBasicConstrain
        }

        let asn1 = try ASN1(from: InputByteStream(octetString))
        guard case .sequence(let constrains) = asn1.content else {
            throw X509.Error.invalidExtensionBasicConstrain
        }

        self.isCritical = isCritical

        // TODO: test
        guard constrains.count <= 2 else {
            throw X509.Error.invalidExtensionBasicConstrain
        }

        if constrains.count >= 1 {
            // BOOLEAN DEFAULT FALSE
            guard case .boolean(let isCA) = constrains[1].content else {
                throw X509.Error.invalidExtensionBasicConstrain
            }
            self.isCA = isCA
        } else {
            self.isCA = false
        }

        if constrains.count == 2 {
            // INTEGER (0..MAX) OPTIONAL
            guard case .integer(let .sane(pathLen)) = constrains[2].content else {
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
    public init(from asn1: ASN1) throws {
        guard case .sequence(let sequence) = asn1.content,
            sequence.count >= 2,
            let object = sequence.first,
            object.identifier.tag == .objectIdentifier,
            case .data(let id) = object.content else
        {
            throw X509.Error.invalidSignature
        }
        switch id {
        case ASN1.Objects.rsaEncryption:
            self = .rsaEncryption
        case ASN1.Objects.sha256WithRSAEncryption:
            self = .sha256WithRSAEncryption
        default:
            throw X509.Error.unimplementedAlgorithm(String(oid: id))
        }
        // TODO: imlement parameters
        let parameters = sequence[1]
        guard parameters.identifier.tag == .null else {
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
        guard asn1.identifier.tag == .bitString,
            case .data(let data) = asn1.content,
            data.count >= 2 else
        {
            return nil
        }
        self.padding = Int(data[0])
        self.bytes = [UInt8](data[1...])
    }
}
