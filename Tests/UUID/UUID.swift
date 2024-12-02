import Testing

@testable import UUID

@Test("UUID")
private func uuid() async throws {
    _ = UUID()
}

@Test("EncodeUUIDString")
private func encodeUUIDString() async throws {
    let uuid = UUID()
    let uuidString = uuid.uuidString
    #expect(uuidString.count == 36)
    let parts = uuidString.split(separator: "-")
    #expect(parts.count == 5)
    if parts.count == 5 {
        // UUID version
        #expect(parts[2].first == "4")
    }
}

@Test("DecodeUUIDString")
private func decodeUUIDString() async throws {
    let uuid = UUID()
    let uuidString = uuid.uuidString
    #expect(UUID(uuidString: uuidString) == uuid)
}

@Test("Namespace")
private func namespace() async throws {
    #expect(UUID.dns.uuidString == "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    #expect(UUID.url.uuidString == "6ba7b811-9dad-11d1-80b4-00c04fd430c8")
    #expect(UUID.oid.uuidString == "6ba7b812-9dad-11d1-80b4-00c04fd430c8")
    #expect(UUID.x500.uuidString == "6ba7b814-9dad-11d1-80b4-00c04fd430c8")
}

@Test("UUIDv5")
private func uuidV5() async throws {
    let uuid = UUID(namespace: .dns, name: "swiftstack.io")
    #expect(uuid.uuidString == "47173f2b-f3b6-5d00-be40-70d315ed9a8a")
}
