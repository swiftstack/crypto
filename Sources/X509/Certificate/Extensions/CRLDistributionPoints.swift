import ASN1

extension Certificate.Extension {
    public struct CRLDistributionPoints: Equatable {
        public let distributionPoints: [DistributionPoint]

        public struct DistributionPoint: Equatable {
            public var name: Name?
            public var reasons: Reasons?
            public var crlIssuer: GeneralNames?

            public init(
                name: Name? = nil,
                reasons: Reasons? = nil,
                crlIssuer: GeneralNames? = nil)
            {
                self.name = name
                self.reasons = reasons
                self.crlIssuer = crlIssuer
            }

            public enum Name: Equatable {
                case full(GeneralNames)
                case relativeToCRLIssuer(RelativeDistinguishedName)
            }

            public struct Reasons: OptionSet, Equatable {
                public let rawValue: UInt16

                public init(rawValue: UInt16) {
                    self.rawValue = rawValue
                }

                // TODO: verify with a dump of real world usage
                public static let unused = Reasons(rawValue: 1 << 15)
                public static let keyCompromise = Reasons(rawValue: 1 << 14)
                public static let caCompromise = Reasons(rawValue: 1 << 13)
                public static let affiliationChanged = Reasons(rawValue: 1 << 12)
                public static let superseded = Reasons(rawValue: 1 << 11)
                public static let cessationOfOperation = Reasons(rawValue: 1 << 10)
                public static let certificateHold = Reasons(rawValue: 1 << 9)
                public static let privilegeWithdrawn = Reasons(rawValue: 1 << 8)
                public static let aaCompromise = Reasons(rawValue: 1 << 7)
            }
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.13

typealias Extension = Certificate.Extension

extension Extension.CRLDistributionPoints {
    public init(from asn1: ASN1) throws {
        // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
        guard let sequence = asn1.sequenceValue,
            sequence.count > 0 else
        {
            throw X509.Error(.invalidCRLDistributionPoints, asn1)
        }
        self.distributionPoints = try sequence.map(DistributionPoint.init)
    }
}

extension Extension.CRLDistributionPoints.DistributionPoint {
    // DistributionPoint ::= SEQUENCE {
    //     distributionPoint       [0]     DistributionPointName OPTIONAL,
    //     reasons                 [1]     ReasonFlags OPTIONAL,
    //     cRLIssuer               [2]     GeneralNames OPTIONAL }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count <= 3 else
        {
            throw X509.Error(.invalidDistributionPoint, asn1)
        }
        self.init()
        for item in sequence {
            guard let value = item.sequenceValue?.first else {
                throw X509.Error(.invalidDistributionPoint, asn1)
            }
            switch item.tag.rawValue {
            case 0: self.name = try .init(from: value)
            case 1: self.reasons = try .init(from: value)
            case 2: self.crlIssuer = try .init(from: value)
            default: throw X509.Error(.invalidDistributionPoint, item)
            }
        }
    }
}

extension Extension.CRLDistributionPoints.DistributionPoint.Name {
    // DistributionPointName ::= CHOICE {
    //     fullName                [0]     GeneralNames,
    //     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
    public init(from asn1: ASN1) throws {
        guard asn1.class == .contextSpecific else {
            throw X509.Error(.invalidDistributionPointName, asn1)
        }
        switch asn1.tag.rawValue {
        case 0: self = .full(try .init(from: asn1))
        case 1: self = .relativeToCRLIssuer(try .init(from: asn1))
        default: throw X509.Error(.invalidDistributionPointName, asn1)
        }
    }
}

extension Extension.CRLDistributionPoints.DistributionPoint.Reasons {
    // ReasonFlags ::= BIT STRING {
    //     unused                  (0),
    //     keyCompromise           (1),
    //     cACompromise            (2),
    //     affiliationChanged      (3),
    //     superseded              (4),
    //     cessationOfOperation    (5),
    //     certificateHold         (6),
    //     privilegeWithdrawn      (7),
    //     aACompromise            (8) }
    public init(from asn1: ASN1) throws {
        guard asn1.tag == .bitString,
            let data = asn1.dataValue,
            data.count == 2 else
        {
            throw X509.Error(.invalidDistributionPointReasons, asn1)
        }
        self.rawValue = UInt16(data[0]) << 8 | UInt16(data[1])
    }
}
