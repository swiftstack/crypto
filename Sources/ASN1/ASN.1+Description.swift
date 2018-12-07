import Hex

extension String {
    func shiftingRight(by spaces: Int) -> String {
        let lines = self.split(separator: "\n")
        return lines[0] + "\n" + lines[1...]
            .map{ String(repeating: " ", count: spaces) + $0 }
            .joined(separator: "\n")
    }
}

extension ASN1: CustomStringConvertible {
    func prettyDescription(level: Int) -> String {
        return """

        .init(
            identifier: \(identifier.prettyDescription(level: level + 1)),
            content: \(content.prettyDescription(level: level + 1)))
        """.shiftingRight(by: level * 4)
    }

    public var description: String {
        return prettyDescription(level: 0)
    }
}

extension ASN1.Identifier: CustomStringConvertible {
    func prettyDescription(level: Int) -> String {
        return """

        .init(
            isConstructed: \(isConstructed),
            class: .\(`class`),
            tag: .\(tag))
        """.shiftingRight(by: level * 4)
    }

    public var description: String {
        return prettyDescription(level: 0)
    }
}

extension ASN1.Content: CustomStringConvertible {
    func prettyDescription(level: Int) -> String {
        let description: String
        switch self {
        case .boolean(let value):
            description = """
                .boolean(\(value))
                """
        case .integer(let value):
            description = """
                .integer(\(value))
                """
        case .string(let value):
            description = """
                .string(\"\(value)\")
                """
        case .data(let value):
            description = """
                .data(\(String(encodingToHex: value))
                """
        case .sequence(let value):
            description = """
                .sequence(\(value))
                """
        case .objectIdentifier(let value):
            description = """
                .objectIdentifier(\(value))
                """
        }
        return description.shiftingRight(by: level * 4)
    }

    public var description: String {
        return prettyDescription(level: 0)
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
        case .other(let value):
            return ".other(\(value))"
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
        case .subjectKeyIdentifier: return ".subjectKeyIdentifier"
        case .keyUsage: return ".keyUsage"
        case .basicConstrains: return ".basicConstrains"
        case .crlDistributionPoints: return ".crlDistributionPoints"
        case .certificatePolicies: return ".certificatePolicies"
        case .authorityKeyIdentifier: return ".authorityKeyIdentifier"
        case .extKeyUsage: return ".extKeyUsage"
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
