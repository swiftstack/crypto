import Hex

extension Array where Element == ASN1 {
    func dump(format: Format) -> String {
        guard !self.isEmpty else {
            return "[]"
        }
        var result = "["
        let prefix = format.nextLevel.prefix
        for item in self {
            result += "\n"
            result += prefix
            result += item.dump(format: format.nextLevel)
            result += ","
        }
        result.removeLast()
        result += "\n"
        result += format.prefix
        result += "]"
        return result
    }
}

extension ASN1: CustomStringConvertible {
    func dump(format: Format) -> String {
        let prefix = format.nextLevel.prefix
        return """
            .init(
            \(prefix)identifier: \(identifier.dump(format: format.nextLevel)),
            \(prefix)content: \(content.dump(format: format.nextLevel)))
            """
    }

    public var description: String {
        return dump(format: .prettify)
    }
}

extension ASN1.Identifier: CustomStringConvertible {
    func dump(format: Format) -> String {
        let prefix = format.nextLevel.prefix
        return """
            .init(
            \(prefix)isConstructed: \(isConstructed),
            \(prefix)class: .\(`class`),
            \(prefix)tag: .\(tag))
            """
    }

    public var description: String {
        return dump(format: .prettify)
    }
}

extension ASN1.Content: CustomStringConvertible {
    func dump(format: Format) -> String {
        switch self {
        case .boolean(let value):
            return ".boolean(\(value))"
        case .integer(let value):
            return ".integer(\(value))"
        case .string(let value):
            return ".string(\"\(value)\")"
        case .data(let value):
            return ".data([\(String(encodingToHex: value))])"
        case .sequence(let value):
            return ".sequence(\(value.dump(format: format)))"
        case .objectIdentifier(let value):
            return ".objectIdentifier(\(value))"
        }
    }

    public var description: String {
        return dump(format: .prettify)
    }
}

extension ASN1.ObjectIdentifier: CustomStringConvertible {
    public var description: String {
        switch self {
        case .sha256WithRSAEncryption:
            return ".sha256WithRSAEncryption"
        case .rsaEncryption:
            return ".rsaEncryption"
        case .attribute(.none):
            return ".attribute"
        case .attribute(.some(let value)):
            return ".attribute(\(value))"
        case .certificateExtension(.none):
            return ".certificateExtension"
        case .certificateExtension(.some(let value)):
            return ".certificateExtension(\(value))"
        case .pkix(.none):
            return ".pkix"
        case .pkix(.some(let value)):
            return ".pkix(\(value))"
        case .netscape(.none):
            return ".netscape"
        case .netscape(.some(let value)):
            return ".netscape(\(value))"
        case .other:
            return ".other(\"\(stringValue)\")"
        }
    }
}

extension ASN1.ObjectIdentifier.Attribute: CustomStringConvertible {
    public var description: String {
        switch self {
        case .name: return ".name"
        case .surname: return ".surname"
        case .givenName: return ".givenName"
        case .initials: return ".initials"
        case .generationQualifier: return ".generationQualifier"
        case .commonName: return ".commonName"
        case .localityName: return ".localityName"
        case .stateOrProvinceName: return ".stateOrProvinceName"
        case .organizationName: return ".organizationName"
        case .organizationalUnitName: return ".organizationalUnitName"
        case .title: return ".title"
        case .dnQualifier: return ".dnQualifier"
        case .countryName: return ".countryName"
        case .serialNumber: return ".serialNumber"
        case .pseudonym: return ".pseudonym"
        }
    }
}

extension ASN1.ObjectIdentifier.CertificateExtension: CustomStringConvertible {
    public var description: String {
        switch self {
        case .subjectKeyIdentifier:
            return ".subjectKeyIdentifier"
        case .keyUsage:
            return ".keyUsage"
        case .subjectAltName:
            return ".subjectAltName"
        case .basicConstrains:
            return ".basicConstrains"
        case .crlDistributionPoints:
            return ".crlDistributionPoints"
        case .certificatePolicies(let value):
            return ".certificatePolicies(\(String(describing: value)))"
        case .authorityKeyIdentifier:
            return ".authorityKeyIdentifier"
        case .extKeyUsage:
            return ".extKeyUsage"
        }
    }
}

extension ASN1.ObjectIdentifier.Pkix: CustomStringConvertible {
    public var description: String {
        switch self {
        case .extension(.authorityInfoAccessSyntax):
            return ".extension(.authorityInfoAccessSyntax)"
        case .policyQualifier(.cps):
            return ".policyQualifier(.cps)"
        case .policyQualifier(.unotice):
            return ".policyQualifier(.unotice)"
        case .keyPurpose(.serverAuth):
            return ".keyPurpose(.serverAuth)"
        case .keyPurpose(.clientAuth):
            return ".keyPurpose(.clientAuth)"
        case .keyPurpose(.other(let id)):
            return ".keyPurpose(.other(\(id.stringValue)))"
        case .accessDescription(.oscp(.basicResponse)):
            return ".accessDescription(.oscp(.basicResponse))"
        case .accessDescription(.oscp(.nonce)):
            return ".accessDescription(.oscp(.nonce))"
        case .accessDescription(.oscp(.crlReference)):
            return ".accessDescription(.oscp(.crlReference))"
        case .accessDescription(.oscp(.nocheck)):
            return ".accessDescription(.oscp(.nocheck))"
        case .accessDescription(.caIssuers):
            return ".accessDescription(.caIssuers)"
        case .accessDescription(.timeStamping):
            return ".accessDescription(.timeStamping)"
        case .accessDescription(.caRepository):
            return ".accessDescription(.caRepository)"
        }
    }
}

extension ASN1.ObjectIdentifier.Netscape: CustomStringConvertible {
    public var description: String {
        switch self {
        case .certificateExtension(.certificateType):
            return ".certificateExtension(.certificateType)"
        }
    }
}

enum Format {
    case compact
    case prettify
    case prettifyAt(level: Int)

    var isPrettify: Bool {
        switch self {
        case .compact: return false
        case .prettify: return true
        case .prettifyAt: return true
        }
    }

    var level: Int {
        switch self {
        case .compact: return 0
        case .prettify: return 0
        case .prettifyAt(let level): return level
        }
    }

    var nextLevel: Format {
        switch self {
        case .compact: return .compact
        case .prettify: return .prettifyAt(level: 1)
        case .prettifyAt(let level): return .prettifyAt(level: level + 1)
        }
    }

    var parentLevel: Format {
        switch self {
        case .compact: return .compact
        case .prettify: return .prettify
        case .prettifyAt(let level): return .prettifyAt(level: level - 1)
        }
    }

    var prefix: String {
        switch level {
        case ...0: return ""
        default: return .init(repeating: " ", count: level * 4)
        }
    }
}
