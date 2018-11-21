import ASN1
import Stream

extension Certificate {
    public struct Identifier: Equatable {
        public let name: String
        public let country: String
        public let locality: String?
        public let stateOrProvince: String?
        public let organization: String
        public let organizationalUnit: String?

        public init(
            country: String,
            organization: String,
            organizationalUnit: String? = nil,
            locality: String? = nil,
            stateOrProvince: String? = nil,
            name: String)
        {
            self.country = country
            self.organization = organization
            self.organizationalUnit = organizationalUnit
            self.locality = locality
            self.stateOrProvince = stateOrProvince
            self.name = name
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.4

extension Certificate.Identifier {
    typealias OID = ASN1.Objects

    public init(from asn1: ASN1) throws {
        var nameRequired: String? = nil
        var countryRequired: String? = nil
        var organizationRequired: String? = nil
        var organizationalUnit: String? = nil
        var locality: String? = nil
        var stateOrProvince: String? = nil

        guard let sequence = asn1.sequenceValue else {
            throw X509.Error.invalidIdentifier
        }

        for item in sequence {
            guard
                item.tag == .set,
                let set = item.sequenceValue,
                set.count == 1,
                let sequence = set[0].sequenceValue,
                sequence.count == 2,
                sequence[0].tag == .objectIdentifier,
                let id = sequence[0].dataValue,
                let value = sequence[1].stringValue else
            {
                throw X509.Error.invalidIdentifier
            }
            switch id {
            case OID.countryName:
                countryRequired = value
            case OID.organizationName:
                organizationRequired = value
            case OID.organizationalUnitName:
                organizationalUnit = value
            case OID.localityName:
                locality = value
            case OID.stateOrProvinceName:
                stateOrProvince = value
            case OID.commonName:
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