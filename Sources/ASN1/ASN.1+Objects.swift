extension ASN1 {
    public enum Objects {
        public static let basicOCSP: [UInt8] = [
            0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
        ]

        public static let sha256WithRSAEncryption: [UInt8] = [
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
        ]

        public static let rsaEncryption: [UInt8] = [
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
        ]

        // MARK: id-at-*

        public static let commonName: [UInt8] = [0x55, 0x04, 0x03]
        public static let countryName: [UInt8] = [0x55, 0x04, 0x06]
        public static let localityName: [UInt8] = [0x55, 0x04, 0x07]
        public static let stateOrProvinceName: [UInt8] = [0x55, 0x04, 0x08]
        public static let organizationName: [UInt8] = [0x55, 0x04, 0x0a]
        public static let organizationalUnitName: [UInt8] = [0x55, 0x04, 0x0b]

        // MARK: id-ce-*

        public enum CertificateExtension {
            static let prefix: [UInt8] = [0x55, 0x1d]
            public static let subjectKeyIdentifier = prefix + [0x0e]
            public static let keyUsage = prefix + [0x0f]
            public static let basicConstrains = prefix + [0x13]
            public static let cRLDistributionPoints = prefix + [0x1f]
            public static let certificatePolicies = prefix + [0x20]
            public static let authorityKeyIdentifier = prefix + [0x23]
            public static let extKeyUsage = prefix + [0x25]
        }

        public enum Pkix {
            static let prefix: [UInt8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07]
            // 1.3.6.1.5.5.7.48.1
            public static let pkix48_1 = prefix + [0x30, 0x01]
            // 1.3.6.1.5.5.7.48.2
            public static let pkix48_2 = prefix + [0x30, 0x02]

            public enum Extension {
                static let prefix: [UInt8] = Pkix.prefix + [0x01]
                // 1.3.6.1.5.5.7.1.1
                public static let authorityInfoAccessSyntax = prefix + [0x01]
            }
        }
    }
}
