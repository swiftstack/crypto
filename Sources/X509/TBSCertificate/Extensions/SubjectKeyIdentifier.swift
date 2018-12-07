import ASN1

extension TBSCertificate.Extension {
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.2
    public typealias SubjectKeyIdentifier = KeyIdentifier
}
