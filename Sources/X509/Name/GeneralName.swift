import ASN1
import Stream

public enum GeneralName: Equatable {
    case otherName(OtherName)
    case rfc822Name(String)
    case dnsName(String)
    case x400Address(ORAddress)
    case directoryName(Name)
    case ediPartyName(EDIPartyName)
    case uniformResourceIdentifier(String)
    case ipAddress([UInt8])
    case registeredId(ASN1.ObjectIdentifier)
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.6

public typealias GeneralNames = [GeneralName]
// IssuerAltName ::= GeneralNames
public typealias IssuerAltName = GeneralNames

extension Array where Element == GeneralName {
    // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            sequence.count >= 1 else
        {
            throw Error.invalidASN1(asn1)
        }
        self = try sequence.map(GeneralName.init)
    }
}

extension GeneralName {
    public enum Tag: UInt8 {
        case otherName                 = 0
        case rfc822Name                = 1
        case dnsName                   = 2
        case x400Address               = 3
        case directoryName             = 4
        case ediPartyName              = 5
        case uniformResourceIdentifier = 6
        case ipAddress                 = 7
        case registeredId              = 8
    }
    // GeneralName ::= CHOICE {
    //   otherName                       [0]     OtherName,
    //   rfc822Name                      [1]     IA5String,
    //   dNSName                         [2]     IA5String,
    //   x400Address                     [3]     ORAddress,
    //   directoryName                   [4]     Name,
    //   ediPartyName                    [5]     EDIPartyName,
    //   uniformResourceIdentifier       [6]     IA5String,
    //   iPAddress                       [7]     OCTET STRING,
    //   registeredID                    [8]     OBJECT IDENTIFIER }
    public init(from asn1: ASN1) throws {
        guard asn1.class == .contextSpecific,
            let tag = Tag(rawValue: asn1.tag.rawValue) else
        {
            throw Error.invalidASN1(asn1)
        }
        switch tag {
        case .otherName: try self.init(decodingOtherName: asn1)
        case .rfc822Name: try self.init(decodingRFC822Name: asn1)
        case .dnsName: try self.init(decodingDNSName: asn1)
        case .x400Address: try self.init(decodingX400Address: asn1)
        case .directoryName: try self.init(decodingDirectoryName: asn1)
        case .ediPartyName: try self.init(decodingEDIPartyName: asn1)
        case .uniformResourceIdentifier: try self.init(decodingURI: asn1)
        case .ipAddress: try self.init(decodingIPAddress: asn1)
        case .registeredId: try self.init(decodingRegisteredId: asn1)
        }
    }

    private init(decodingOtherName asn1: ASN1) throws {
        self = .otherName(try .init(from: asn1))
    }

    private init(decodingRFC822Name asn1: ASN1) throws {
        guard let string = asn1.stringValue else {
            throw Error.invalidASN1(asn1)
        }
        self = .rfc822Name(string)
    }

    // TODO: test
    private init(decodingDNSName asn1: ASN1) throws {
        guard case .integer(.insane(let storage)) = asn1.content else {
            throw Error.invalidASN1(asn1)
        }
        self = .dnsName(String(decoding: storage.bytes, as: UTF8.self))
    }

    private init(decodingX400Address asn1: ASN1) throws {
        self = .x400Address(try .init(from: asn1))
    }

    private init(decodingDirectoryName asn1: ASN1) throws {
        // TODO: test why this is nested
        guard let sequence = asn1.sequenceValue, sequence.count == 1 else {
            throw Error.invalidASN1(asn1)
        }
        self = .directoryName(try .init(from: sequence[0]))
    }

    private init(decodingEDIPartyName asn1: ASN1) throws {
        self = .ediPartyName(try .init(from: asn1))
    }

    private init(decodingURI asn1: ASN1) throws {
        guard let string = asn1.stringIdentifierValue else {
            throw Error.invalidASN1(asn1)
        }
        self = .uniformResourceIdentifier(string)
    }

    private init(decodingIPAddress asn1: ASN1) throws {
        guard let bytes = asn1.dataValue else {
            throw Error.invalidASN1(asn1)
        }
        self = .ipAddress(bytes)
    }

    private init(decodingRegisteredId asn1: ASN1) throws {
        guard let bytes = asn1.dataValue else {
            throw Error.invalidASN1(asn1)
        }
        self = .registeredId(.init(rawValue: bytes))
    }
}
