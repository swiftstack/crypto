import Stream

extension ASN1 {
    // TODO: restructure?
    public enum ObjectIdentifier: Equatable, Hashable, Sendable {
        case sha256WithRSAEncryption
        case rsaEncryption
        // MARK: id-at-*
        case attribute(Attribute?)
        // MARK: id-ce-*
        case certificateExtension(CertificateExtension?)
        // MARK: id-pkix-*
        case pkix(Pkix?)
        case netscape(Netscape?)
        // MARK: unknown
        case other([UInt8])

        public enum Attribute: Equatable, Hashable, Sendable {
            case name
            case surname
            case givenName
            case initials
            case generationQualifier
            case commonName
            case localityName
            case stateOrProvinceName
            case organizationName
            case organizationalUnitName
            case title
            case dnQualifier
            case countryName
            case serialNumber
            case pseudonym
        }

        public enum CertificateExtension: Equatable, Hashable, Sendable {
            case subjectKeyIdentifier
            case keyUsage
            case subjectAltName
            case basicConstrains
            case crlDistributionPoints
            case certificatePolicies(CertificatePolicy?)
            case authorityKeyIdentifier
            case extKeyUsage

            public enum CertificatePolicy: Sendable {
                case any
            }
        }

        public enum Pkix: Equatable, Hashable, Sendable {
            case `extension`(Extension)
            case policyQualifier(PolicyQualifier)
            case keyPurpose(KeyPurpose)
            case accessDescription(AccessDescription)

            public enum Extension: Equatable, Hashable, Sendable {
                case authorityInfoAccessSyntax
            }

            public enum PolicyQualifier: Sendable {
                case cps
                case unotice
            }

            public enum KeyPurpose: Equatable, Sendable {
                case serverAuth
                case clientAuth
                // TODO: delete?
                indirect case other(ASN1.ObjectIdentifier)
            }

            public enum AccessDescription: Equatable, Hashable, Sendable {
                case oscp(OSCP)
                case caIssuers
                case timeStamping
                case caRepository

                public enum OSCP: Equatable, Hashable, Sendable {
                    case basicResponse
                    case nonce
                    case crlReference
                    case nocheck
                }
            }
        }

        public enum Netscape: Sendable {
            case `certificateExtension`(CertificateExtension)

            public enum CertificateExtension: Sendable {
                case certificateType
            }
        }
    }

    enum ObjectIdentifierBytes {
        static let sha256WithRSAEncryption: [UInt8] = [
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
        ]

        static let rsaEncryption: [UInt8] = [
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
        ]

        // MARK: id-at-*

        enum Attribute {
            // id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
            static let objectId: [UInt8] = [0x55, 0x04]
            // Naming attributes of type X520name
            static let name: [UInt8] = objectId + [0x29]
            static let surname: [UInt8] = objectId + [0x04]
            static let givenName: [UInt8] = objectId + [0x2a]
            static let initials: [UInt8] = objectId + [0x2b]
            static let generationQualifier: [UInt8] = objectId + [0x2c]
            // Naming attributes of type X520CommonName
            static let commonName: [UInt8] = objectId + [0x03]
            // Naming attributes of type X520LocalityName
            static let localityName: [UInt8] = objectId + [0x07]
            // Naming attributes of type X520StateOrProvinceName
            static let stateOrProvinceName: [UInt8] = objectId + [0x08]
            // Naming attributes of type X520OrganizationName
            static let organizationName: [UInt8] = objectId + [0x0a]
            // Naming attributes of type X520OrganizationalUnitName
            static let organizationalUnitName: [UInt8] = objectId + [0x0b]
            // Naming attributes of type X520Title
            static let title: [UInt8] = objectId + [0x0c]
            // Naming attributes of type X520dnQualifier
            static let dnQualifier: [UInt8] = objectId + [0x2e]
            // Naming attributes of type X520countryName (digraph from IS 3166)
            static let countryName: [UInt8] = objectId + [0x06]
            // Naming attributes of type X520SerialNumber
            static let serialNumber: [UInt8] = objectId + [0x05]
            // Naming attributes of type X520Pseudonym
            static let pseudonym: [UInt8] = objectId + [0x41]
        }

        // MARK: id-ce-*

        enum CertificateExtension {
            static let objectId: [UInt8] = [0x55, 0x1d]
            static let subjectKeyIdentifier = objectId + [0x0e]
            static let keyUsage = objectId + [0x0f]
            static let subjectAltName = objectId + [0x11]
            static let basicConstrains = objectId + [0x13]
            static let crlDistributionPoints = objectId + [0x1f]
            static let authorityKeyIdentifier = objectId + [0x23]
            static let extKeyUsage = objectId + [0x25]

            enum CertificatePolicies {
                static let objectId: [UInt8] =
                    CertificateExtension.objectId + [0x20]

                static let any = objectId + [0x00]
            }
        }

        enum Pkix {
            // 1.3.6.1.5.5.7.*
            static let objectId: [UInt8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07]

            enum Extension {
                // 1.3.6.1.5.5.7.1.*
                static let objectId: [UInt8] = Pkix.objectId + [0x01]
                // 1.3.6.1.5.5.7.1.1
                static let authorityInfoAccessSyntax = objectId + [0x01]
            }

            enum PolicyQualifier {
                // 1.3.6.1.5.5.7.2.*
                static let objectId: [UInt8] = Pkix.objectId + [0x02]

                static let cps = objectId + [0x01]
                static let unotice = objectId + [0x02]
            }

            enum KeyPurpose {
                // 1.3.6.1.5.5.7.3.*
                static let objectId: [UInt8] = Pkix.objectId + [0x03]

                static let serverAuth = objectId + [0x01]
                static let clientAuth = objectId + [0x02]
            }

            enum AccessDescription {
                // 1.3.6.1.5.5.7.48.*
                static let objectId: [UInt8] = Pkix.objectId + [0x30]

                enum OSCP {
                    // 1.3.6.1.5.5.7.48.1.*
                    static let objectId: [UInt8] =
                        AccessDescription.objectId + [0x01]
                    static let basicResponse = objectId + [0x01]
                    static let nonce = objectId + [0x02]
                    static let crlReference = objectId + [0x03]
                    static let nocheck = objectId + [0x05]
                }

                static let caIssuers: [UInt8] = objectId + [0x02]
                static let timeStamping: [UInt8] = objectId + [0x03]
                static let caRepository: [UInt8] = objectId + [0x05]
            }
        }

        // MARK: Netscape Certificate Extensions

        enum Netscape {
            // 2.16.840.1.113730 (netscape)
            static let objectId: [UInt8] = [
                0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42]

            enum CertificateExtension {
                // 2.16.840.1.113730.1 (cert-ext)
                static let objectId: [UInt8] = Netscape.objectId + [0x01]
                // 2.16.840.1.113730.1.1 (cert-type)
                static let certificateType: [UInt8] = objectId + [0x01]
            }
        }
    }
}

// TODO: optimize, this is just a stub

public protocol ObjectIdentifierProtocol: RawRepresentable
    where RawValue == [UInt8] {}

// MARK: ObjectIdentifier

extension ASN1.ObjectIdentifier: ObjectIdentifierProtocol {
    typealias Raw = ASN1.ObjectIdentifierBytes

    public var rawValue: [UInt8] {
        switch self {
        case .sha256WithRSAEncryption:
            return Raw.sha256WithRSAEncryption
        case .rsaEncryption:
            return Raw.rsaEncryption
        case .attribute(.none):
            return Raw.Attribute.objectId
        case .attribute(.some(let value)):
             return value.rawValue
        case .certificateExtension(.none):
            return Raw.CertificateExtension.objectId
        case .certificateExtension(.some(let value)):
            return value.rawValue
        case .pkix(.none):
            return Raw.Pkix.objectId
        case .pkix(.some(let value)):
            return value.rawValue
        case .netscape(.none):
            return Raw.Netscape.objectId
        case .netscape(.some(let value)):
            return value.rawValue
        case .other(let value):
            return value
        }
    }

    public init(rawValue bytes: [UInt8]) {
        switch bytes {
        case Raw.sha256WithRSAEncryption:
            self = .sha256WithRSAEncryption
        case Raw.rsaEncryption:
            self = .rsaEncryption
        case _ where bytes.starts(with: Raw.Attribute.objectId):
            switch Attribute(rawValue: bytes) {
            case .some(let value): self = .attribute(value)
            case .none: self = .other(bytes)
            }
        case _ where bytes.starts(with: Raw.CertificateExtension.objectId):
            switch CertificateExtension(rawValue: bytes) {
            case .some(let value): self = .certificateExtension(value)
            case .none: self = .other(bytes)
            }
        case _ where bytes.starts(with: Raw.Pkix.objectId):
            switch Pkix(rawValue: bytes) {
            case .some(let value): self = .pkix(value)
            case .none: self = .other(bytes)
            }
        case _ where bytes.starts(with: Raw.Netscape.objectId):
            switch Netscape(rawValue: bytes) {
            case .some(let value): self = .netscape(value)
            case .none: self = .other(bytes)
            }
        default:
            self = .other(bytes)
        }
    }
}

// MARK: ObjectIdentifier.Attribute

extension ASN1.ObjectIdentifier.Attribute: ObjectIdentifierProtocol {
    typealias Raw = ASN1.ObjectIdentifierBytes.Attribute

    public var rawValue: [UInt8] {
        switch self {
        case .name: return Raw.name
        case .surname: return Raw.surname
        case .givenName: return Raw.givenName
        case .initials: return Raw.initials
        case .generationQualifier: return Raw.generationQualifier
        case .commonName: return Raw.commonName
        case .localityName: return Raw.localityName
        case .stateOrProvinceName: return Raw.stateOrProvinceName
        case .organizationName: return Raw.organizationName
        case .organizationalUnitName: return Raw.organizationalUnitName
        case .title: return Raw.title
        case .dnQualifier: return Raw.dnQualifier
        case .countryName: return Raw.countryName
        case .serialNumber: return Raw.serialNumber
        case .pseudonym: return Raw.pseudonym
        }
    }

    public init?(rawValue bytes: [UInt8]) {
        switch bytes {
        case Raw.name: self = .name
        case Raw.surname: self = .surname
        case Raw.givenName: self = .givenName
        case Raw.initials: self = .initials
        case Raw.generationQualifier: self = .generationQualifier
        case Raw.commonName: self = .commonName
        case Raw.localityName: self = .localityName
        case Raw.stateOrProvinceName: self = .stateOrProvinceName
        case Raw.organizationName: self = .organizationName
        case Raw.organizationalUnitName: self = .organizationalUnitName
        case Raw.title: self = .title
        case Raw.dnQualifier: self = .dnQualifier
        case Raw.countryName: self = .countryName
        case Raw.serialNumber: self = .serialNumber
        case Raw.pseudonym: self = .pseudonym
        default: return nil
        }
    }
}

// MARK: ObjectIdentifier.CertificateExtension

extension ASN1.ObjectIdentifier.CertificateExtension: ObjectIdentifierProtocol {
    typealias Raw = ASN1.ObjectIdentifierBytes.CertificateExtension
    typealias CertificatePolicies = Raw.CertificatePolicies

    public var rawValue: [UInt8] {
        switch self {
        case .subjectKeyIdentifier: return Raw.subjectKeyIdentifier
        case .keyUsage: return Raw.keyUsage
        case .subjectAltName: return Raw.subjectAltName
        case .basicConstrains: return Raw.basicConstrains
        case .crlDistributionPoints: return Raw.crlDistributionPoints
        case .certificatePolicies(.none): return CertificatePolicies.objectId
        case .certificatePolicies(.some(.any)): return CertificatePolicies.any
        case .authorityKeyIdentifier: return Raw.authorityKeyIdentifier
        case .extKeyUsage: return Raw.extKeyUsage
        }
    }

    public init?(rawValue bytes: [UInt8]) {
        switch bytes {
        case Raw.subjectKeyIdentifier: self = .subjectKeyIdentifier
        case Raw.keyUsage: self = .keyUsage
        case Raw.subjectAltName: self = .subjectAltName
        case Raw.basicConstrains: self = .basicConstrains
        case Raw.crlDistributionPoints: self = .crlDistributionPoints
        case Raw.CertificatePolicies.objectId: self = .certificatePolicies(nil)
        case Raw.CertificatePolicies.any: self = .certificatePolicies(.any)
        case Raw.authorityKeyIdentifier: self = .authorityKeyIdentifier
        case Raw.extKeyUsage: self = .extKeyUsage
        default: return nil
        }
    }
}

// MARK: ObjectIdentifier.Pkix

extension ASN1.ObjectIdentifier.Pkix: ObjectIdentifierProtocol {
    typealias Raw = ASN1.ObjectIdentifierBytes.Pkix

    public var rawValue: [UInt8] {
        switch self {
        case .extension(.authorityInfoAccessSyntax):
            return Raw.Extension.authorityInfoAccessSyntax
        case .policyQualifier(.cps):
            return Raw.PolicyQualifier.cps
        case .policyQualifier(.unotice):
            return Raw.PolicyQualifier.unotice
        case .keyPurpose(.serverAuth):
            return Raw.KeyPurpose.serverAuth
        case .keyPurpose(.clientAuth):
            return Raw.KeyPurpose.clientAuth
        case .keyPurpose(.other(let id)):
            return id.rawValue
        case .accessDescription(.oscp(.basicResponse)):
            return Raw.AccessDescription.OSCP.basicResponse
        case .accessDescription(.oscp(.nonce)):
            return Raw.AccessDescription.OSCP.nonce
        case .accessDescription(.oscp(.crlReference)):
            return Raw.AccessDescription.OSCP.crlReference
        case .accessDescription(.oscp(.nocheck)):
            return Raw.AccessDescription.OSCP.nocheck
        case .accessDescription(.caIssuers):
            return Raw.AccessDescription.caIssuers
        case .accessDescription(.timeStamping):
            return Raw.AccessDescription.timeStamping
        case .accessDescription(.caRepository):
            return Raw.AccessDescription.caRepository
        }
    }

    public init?(rawValue bytes: [UInt8]) {
        switch bytes {
        case Raw.Extension.authorityInfoAccessSyntax:
            self = .extension(.authorityInfoAccessSyntax)
        case Raw.PolicyQualifier.cps:
            self = .policyQualifier(.cps)
        case Raw.PolicyQualifier.unotice:
            self = .policyQualifier(.unotice)
        case Raw.KeyPurpose.serverAuth:
            self = .keyPurpose(.serverAuth)
        case Raw.KeyPurpose.clientAuth:
            self = .keyPurpose(.clientAuth)
        case Raw.AccessDescription.OSCP.basicResponse:
            self = .accessDescription(.oscp(.basicResponse))
        case Raw.AccessDescription.OSCP.nonce:
            self = .accessDescription(.oscp(.nonce))
        case Raw.AccessDescription.OSCP.crlReference:
            self = .accessDescription(.oscp(.crlReference))
        case Raw.AccessDescription.OSCP.nocheck:
            self = .accessDescription(.oscp(.nocheck))
        case Raw.AccessDescription.caIssuers:
            self = .accessDescription(.caIssuers)
        case Raw.AccessDescription.timeStamping:
            self = .accessDescription(.timeStamping)
        case Raw.AccessDescription.caRepository:
            self = .accessDescription(.caRepository)
        default: return nil
        }
    }
}

// MARK: ObjectIdentifier.Netscape

extension ASN1.ObjectIdentifier.Netscape: ObjectIdentifierProtocol {
    typealias Raw = ASN1.ObjectIdentifierBytes.Netscape

    public var rawValue: [UInt8] {
        switch self {
        case .certificateExtension(.certificateType):
            return Raw.CertificateExtension.certificateType
        }
    }

    public init?(rawValue bytes: [UInt8]) {
        switch bytes {
        case Raw.CertificateExtension.certificateType:
            self = .certificateExtension(.certificateType)
        default:
            return nil
        }
    }
}

extension ObjectIdentifierProtocol {
    public var stringValue: String {
        let bytes = rawValue
        guard !bytes.isEmpty else {
            return ""
         }

        var oid: String = "\(bytes[0] / 40).\(bytes[0] % 40)"

        var next = 0
        for byte in bytes[1...] {
            next = (next << 7) | (Int(byte) & 0x7F)
            if (byte & 0x80) == 0 {
                oid.append(".\(next)")
                next = 0
            }
        }

        return oid
    }
}
