 import ASN1

extension Extension {
    public typealias CertificatePolicies = [Policy.Information]

    public enum Policy {
        public struct Information: Equatable {
            public var identifier: ASN1.ObjectIdentifier
            public var qualifiers: [QualifierInfo]

            public init(
                identifier: ASN1.ObjectIdentifier,
                qualifiers: [QualifierInfo])
            {
                self.identifier = identifier
                self.qualifiers = qualifiers
            }
        }

        public enum QualifierInfo: Equatable {
            case cps(String)
            case unotice(UserNotice)
        }

        public struct UserNotice: Equatable {
            public let reference: Reference?
            public let explicitText: DisplayText?

            public struct Reference: Equatable {
                let organization: DisplayText
                let noticeNumbers: [Int]
            }

            public enum DisplayText: Equatable {
                case ia5String(String)
                case visibleString(String)
                case bmpString(String)
                case utf8String(String)
            }
        }
    }
}

// Coding: https://tools.ietf.org/html/rfc5280#section-4.2.1.4

extension Array where Element == Extension.Policy.Information {
    // certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count > 0 else
        {
            throw Error.invalidASN1(asn1)
        }
        self = try sequence.map(Extension.Policy.Information.init)
    }
}

extension Extension.Policy.Information {
    // PolicyInformation ::= SEQUENCE {
    //   policyIdentifier   CertPolicyId,
    //   policyQualifiers   SEQUENCE SIZE (1..MAX) OF
    //                           PolicyQualifierInfo OPTIONAL }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 1 || sequence.count == 2,
            let identifier = sequence[0].objectIdentifierValue else
        {
            throw Error.invalidASN1(asn1)
        }
        self.identifier = identifier
        switch sequence.count {
        case 1: self.qualifiers = []
        case 2: self.qualifiers = try .init(from: sequence[1])
        default: fatalError("unreachable")
        }
    }
}

extension Array where Element == Extension.Policy.QualifierInfo {
    // policyQualifiers   SEQUENCE SIZE (1..MAX) OF
    //                         PolicyQualifierInfo OPTIONAL }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count > 0 else
        {
            throw Error.invalidASN1(asn1)
        }
        self = try sequence.map(Extension.Policy.QualifierInfo.init)
    }
}

extension Extension.Policy.QualifierInfo {
    // PolicyQualifierInfo ::= SEQUENCE {
    //   policyQualifierId  PolicyQualifierId,
    //   qualifier          ANY DEFINED BY policyQualifierId }
    //
    // -- policyQualifierIds for Internet policy qualifiers
    //
    // id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
    // id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
    // id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
    //
    // PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
    //
    // Qualifier ::= CHOICE {
    //   cPSuri           CPSuri,
    //   userNotice       UserNotice }
    //
    // CPSuri ::= IA5String
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2,
            let id = sequence[0].objectIdentifierValue,
            case .pkix(.some(.policyQualifier(let qualifier))) = id else
        {
            throw Error.invalidASN1(asn1)
        }
        func cpsUri(from asn1: ASN1) throws -> String {
            guard let uri = asn1.stringValue else {
                throw Error.invalidASN1(asn1)
            }
            return uri
        }
        switch qualifier {
        case .cps: self = .cps(try cpsUri(from: sequence[1]))
        case .unotice: self = .unotice(try .init(from: sequence[1]))
        }
    }
}

extension Extension.Policy.UserNotice {
    // UserNotice ::= SEQUENCE {
    //   noticeRef        NoticeReference OPTIONAL,
    //   explicitText     DisplayText OPTIONAL }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue else {
            throw Error.invalidASN1(asn1)
        }
        // TODO: test
        switch sequence.count {
        case 0:
            self.reference = nil
            self.explicitText = nil
        case 1:
            self.reference = try .init(from: sequence[0])
            self.explicitText = nil
        case 2:
            self.reference = try .init(from: sequence[0])
            self.explicitText = try .init(from: sequence[1])
        default:
            throw Error.invalidASN1(asn1)
        }
    }
}

extension Extension.Policy.UserNotice.Reference {
    // NoticeReference ::= SEQUENCE {
    //   organization     DisplayText,
    //   noticeNumbers    SEQUENCE OF INTEGER }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count == 2 else
        {
            throw Error.invalidASN1(asn1)
        }
        self.organization = try .init(from: sequence[0])
        self.noticeNumbers = try .init(from: sequence[1])
    }
}

fileprivate extension Array where Element == Int {
    init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue else {
            throw Error.invalidASN1(asn1)
        }
        self = try sequence.map { item in
            guard let integer = item.integerValue else {
                throw Error.invalidASN1(asn1)
            }
            return integer
        }
    }
}

extension Extension.Policy.UserNotice.DisplayText {
    // DisplayText ::= CHOICE {
    //   ia5String        IA5String      (SIZE (1..200)),
    //   visibleString    VisibleString  (SIZE (1..200)),
    //   bmpString        BMPString      (SIZE (1..200)),
    //   utf8String       UTF8String     (SIZE (1..200)) }
    public init(from asn1: ASN1) throws {
        guard let value = asn1.stringValue,
            value.utf8.count >= 1 && value.utf8.count <= 200 else
        {
            throw Error.invalidASN1(asn1)
        }

        switch asn1.tag {
        case .ia5String: self = .ia5String(value)
        case .visibleString: self = .visibleString(value)
        case .bmpString: self = .bmpString(value)
        case .utf8String: self = .utf8String(value)
        default: throw Error.invalidASN1(asn1)
        }
    }
}
