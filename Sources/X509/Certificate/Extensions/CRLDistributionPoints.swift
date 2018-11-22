import ASN1

extension Certificate.Extensions {
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
                public let rawValue: UInt8

                public init(rawValue: UInt8) {
                    self.rawValue = rawValue
                }

                // TODO: inspect, test
                // FIXME: probably invalid
                public static let unused = Reasons(rawValue: 0)
                public static let keyCompromise = Reasons(rawValue: 1 << 7)
                public static let caCompromise = Reasons(rawValue: 1 << 6)
                public static let affiliationChanged = Reasons(rawValue: 1 << 5)
                public static let superseded = Reasons(rawValue: 1 << 4)
                public static let cessationOfOperation = Reasons(rawValue: 1 << 3)
                public static let certificateHold = Reasons(rawValue: 1 << 2)
                public static let privilegeWithdrawn = Reasons(rawValue: 1 << 1)
                public static let aaCompromise = Reasons(rawValue: 1)
            }
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.13

typealias Extension = Certificate.Extensions

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
    public init(from asn1: ASN1) throws {
        // DistributionPoint ::= SEQUENCE {
        //     distributionPoint       [0]     DistributionPointName OPTIONAL,
        //     reasons                 [1]     ReasonFlags OPTIONAL,
        //     cRLIssuer               [2]     GeneralNames OPTIONAL }
        guard let sequence = asn1.sequenceValue,
            sequence.count >= 1 && sequence.count <= 3 else
        {
            throw X509.Error(.invalidDistributionPoint, asn1)
        }

        self.init()

        for item in sequence {
            switch item.tag.rawValue {
            case 0: self.name = try .init(from: item)
            case 1: self.reasons = try .init(from: item)
            case 2: self.crlIssuer = try .init(from: item)
            default: throw X509.Error(.invalidDistributionPoint, asn1)
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
            data.count == 1 else
        {
            throw X509.Error(.invalidDistributionPointReasons, asn1)
        }
        self.rawValue = data[0]
    }
}
