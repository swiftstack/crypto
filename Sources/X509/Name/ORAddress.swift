import ASN1

public struct ORAddress: Equatable {
    public init(from asn1: ASN1) throws {
        throw X509.Error(.unimplemented, asn1)
    }
}
