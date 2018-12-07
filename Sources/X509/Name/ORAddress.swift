import ASN1

public struct ORAddress: Equatable {
    public init(from asn1: ASN1) throws {
        throw X509.Error.unimplemented(.orAddress(.format), data: asn1)
    }
}

// MARK: Error

extension ORAddress {
    public enum Error {
        public enum Origin {
            case format
        }
    }
}
