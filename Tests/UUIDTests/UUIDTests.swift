import Test
@testable import UUID

final class UUIDTests: TestCase {
    func testUUID() {
        let uuid = UUID()
        assertNotNil(uuid)
    }

    func testEncodeUUIDString() {
        let uuid = UUID()
        let uuidString = uuid.uuidString
        assertEqual(uuidString.count, 36)
        let parts = uuidString.split(separator: "-")
        assertEqual(parts.count, 5)
        if parts.count == 5 {
            // UUID version
            assertEqual(parts[2].first, "4")
        }
    }

    func testDecodeUUIDString() {
        let uuid = UUID()
        let uuidString = uuid.uuidString
        assertEqual(UUID(uuidString: uuidString), uuid)
    }

    func testNamespace() {
        assertEqual(UUID.dns.uuidString, "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
        assertEqual(UUID.url.uuidString, "6ba7b811-9dad-11d1-80b4-00c04fd430c8")
        assertEqual(UUID.oid.uuidString, "6ba7b812-9dad-11d1-80b4-00c04fd430c8")
        assertEqual(UUID.x500.uuidString,"6ba7b814-9dad-11d1-80b4-00c04fd430c8")
    }

    func testUUIDv5() {
        let uuid = UUID(namespace: .dns, name: "swiftstack.io")
        assertEqual(uuid.uuidString, "47173f2b-f3b6-5d00-be40-70d315ed9a8a")
    }
}
