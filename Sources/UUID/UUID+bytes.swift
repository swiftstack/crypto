extension UUID {
    public var bytes: [UInt8] {
        var uuid = self
        return withUnsafeBytes(of: &uuid, [UInt8].init)
    }
}
