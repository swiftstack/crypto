import Stream

// FIXME:
extension ASN1 {
    public init(decoding bytes: [UInt8]) async throws {
        try await self.init(from: MemoryStream(bytes))
    }

    public func encode() async throws -> [UInt8] {
        let stream = MemoryStream()
        try await write(to: stream)
        return stream.withUnsafeBufferPointer([UInt8].init)
    }
}

// FIXME:
extension ASN1.Identifier {
    public init(decoding bytes: [UInt8]) async throws {
        try await self.init(from: MemoryStream(bytes))
    }

    public func encode() async throws -> [UInt8] {
        let stream = MemoryStream()
        try await write(to: stream)
        return stream.withUnsafeBufferPointer([UInt8].init)
    }
}
