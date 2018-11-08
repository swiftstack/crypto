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
}
