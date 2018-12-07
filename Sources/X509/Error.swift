import ASN1

public struct Error: Swift.Error {
    public let reason: Reason
    public let origin: Origin
    public let context: ASN1

    init(_ reason: Reason, in origin: Origin, data context: ASN1) {
        self.reason = reason
        self.origin = origin
        self.context = context
    }

    public enum Reason {
        case invalidASN1
        case unimplemented
        case innerError(Swift.Error)
    }

    public enum Origin {
        // root
        case format
        case tbsCertificate(TBSCertificate.Error.Origin)
        case signature(Signature.Error.Origin)
        // tbsCertificate
        case version(Version.Error.Origin)
        case serialNumber(SerialNumber.Error.Origin)
        case name(Name.Error.Origin)
        case validity(Validity.Error.Origin)
        case publicKey(PublicKey.Error.Origin)
        // common structures
        case time(TimeVariant.Error.Origin)
        case attributeTypeAndValue(AttributeTypeAndValue.Error.Origin)
        case directoryString(DirectoryString.Error.Origin)
        case ediPartyName(EDIPartyName.Error.Origin)
        case distinguishedName(Name.Error.Origin)
        case rdnSequence(RDNSequence.Error.Origin)
        case relativeDistinguishedName(RelativeDistinguishedName.Error.Origin)
        case generalName(GeneralName.Error.Origin)
        case otherName(OtherName.Error.Origin)
        case orAddress(ORAddress.Error.Origin)
        // extensions
        case `extension`(Extension.Error.Origin)
        case basicConstrains(Extension.BasicConstrains.Error.Origin)
        case certificatePolicies(Extension.Policy.Error.Origin)
        case crlDistributionPoints(Extension.CRLDistributionPoints.Error.Origin)
        case authorityKeyIdentifier(Extension.AuthorityKeyIdentifier.Error.Origin)
        case keyIdentifier(Extension.KeyIdentifier.Error.Origin)
        case authorityInfoAccess(Extension.AccessDescription.Error.Origin)
        case keyUsage(Extension.KeyUsage.Error.Origin)
    }

    static func invalidASN1(_ asn1: ASN1, in origin: Origin) -> X509.Error {
        return .init(.invalidASN1, in: origin, data: asn1)
    }

    static func unimplemented(_ origin: Origin, data: ASN1) -> X509.Error {
        return .init(.unimplemented, in: origin, data: data)
    }
}
