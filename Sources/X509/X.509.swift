import Time

public struct X509: Equatable {
    public let certificate: Certificate
    public let algorithm: Algorithm
    public let signature: Signature

    public init(
        certificate: Certificate,
        algorithm: Algorithm,
        signature: Signature)
    {
        self.certificate = certificate
        self.algorithm = algorithm
        self.signature = signature
    }
}

public enum Algorithm {
    case sha256WithRSAEncryption
    case rsaEncryption
}

public struct Signature: Equatable {
    public let padding: Int
    public let encrypted: [UInt8]

    public init(padding: Int, encrypted: [UInt8]) {
        self.padding = padding
        self.encrypted = encrypted
    }
}

public struct Certificate: Equatable {
    public let version: Version
    public let serialNumber: SerialNumber
    public let algorithm: Algorithm
    public let issuer: Identifier
    public let validity: Validity
    public let subject: Identifier
    public let publicKey: PublicKey
    public let extensions: Extensions

    public init(
        version: Version,
        serialNumber: SerialNumber,
        algorithm: Algorithm,
        issuer: Identifier,
        validity: Validity,
        subject: Identifier,
        publicKey: PublicKey,
        extensions: Extensions)
    {
        self.version = version
        self.serialNumber = serialNumber
        self.algorithm = algorithm
        self.issuer = issuer
        self.validity = validity
        self.subject = subject
        self.publicKey = publicKey
        self.extensions = extensions
    }

    public enum Version: UInt8, Equatable {
        case v3 = 0x02
    }

    public struct SerialNumber: Equatable {
        let bytes: [UInt8]
    }

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

    public struct Validity: Equatable {
        public let notBefore: Time
        public let notAfter: Time

        public init(notBefore: Time, notAfter: Time) {
            self.notBefore = notBefore
            self.notAfter = notAfter
        }
    }

    public enum PublicKey: Equatable {
        case rsa(modulus: [UInt8], exponent: Int)
    }

    public struct Extensions: Equatable {
        public var basicConstrains: BasicConstrains?

        public init(
            basicConstrains: BasicConstrains? = nil)
        {
            self.basicConstrains = basicConstrains
        }

        public struct BasicConstrains: Equatable {
            public let isCritical: Bool
            public let isCA: Bool
            public let pathLen: Int?

            public init(
                isCritical: Bool,
                isCA: Bool = false,
                pathLen: Int? = nil)
            {
                self.isCritical = isCritical
                self.isCA = isCA
                self.pathLen = pathLen
            }
        }
    }
}
