extension X509 {
    public enum Error: Swift.Error {
        case invalidX509
        case invalidCertificate
        case invalidAlgorithm
        case unimplementedAlgorithm(String)
        case invalidSignature
        case invalidVersion
        case invalidSerialNumber
        case invalidIdentifier
        case unimplementedIdentifierValue(String)
        case invalidValidity
        case unsupportedAlgorithm
        case invalidPublicKey
        case invalidExtensions
        case invalidExtension(String)
        case unimplementedExtension(String)
    }
}
