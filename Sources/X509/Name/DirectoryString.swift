import ASN1

public enum DirectoryString: Equatable {
    case teletexString(String)
    case printableString(String)
    case universalString(String)
    case utf8String(String)
    case bmpString(String)
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.4

extension DirectoryString {
    // DirectoryString ::= CHOICE {
    //     teletexString           TeletexString (SIZE (1..MAX)),
    //     printableString         PrintableString (SIZE (1..MAX)),
    //     universalString         UniversalString (SIZE (1..MAX)),
    //     utf8String              UTF8String (SIZE (1..MAX)),
    //     bmpString               BMPString (SIZE (1..MAX)) }
    public init(from asn1: ASN1) throws {
        guard let value = asn1.stringValue else {
            throw X509.Error.invalidASN1(asn1, in: .directoryString(.format))
        }
        switch asn1.tag {
            case .teletexString: self = .teletexString(value)
            case .printableString: self = .printableString(value)
            case .universalString: self = .universalString(value)
            case .utf8String: self = .utf8String(value)
            case .bmpString: self = .bmpString(value)
            default: throw X509.Error.invalidASN1(asn1, in: .directoryString(.tag))
        }
    }
}

// MARK: Error

extension DirectoryString {
    public enum Error {
        public enum Origin {
            case format
            case tag
        }
    }
}
