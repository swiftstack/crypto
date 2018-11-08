import SHA1

extension UUID {
    /// UUID version 5 - sha1(namespace + name)
    public init(namespace: UUID, name: String) {
        let bytes = namespace.bytes + [UInt8](name.utf8)

        var sha1 = SHA1()
        sha1.update(bytes)
        let hash = sha1.final()

        var uuid = unsafeBitCast(hash.bigEndian, to: (UUID, UInt32).self).0
        uuid.version = .v5
        uuid.clock.clearReserved()
        self = uuid
    }
}
