import Test
@testable import SHA1

class SHA1Tests: TestCase {
    func testSHA1() {
        let bytes = [UInt8]("The quick brown fox jumps over the lazy dog".utf8)
        var sha1 = SHA1()
        sha1.update(bytes)
        let result = sha1.final()
        let expected: SHA1.Hash = .init(
            a: 0x2fd4e1c6,
            b: 0x7a2d28fc,
            c: 0xed849ee1,
            d: 0xbb76e739,
            e: 0x1b93eb12
        )
        assertEqual(result, expected)
    }

    func testSHA1Array() {
        let bytes = [UInt8]("The quick brown fox jumps over the lazy dog".utf8)
        var sha1 = SHA1()
        sha1.update(bytes)
        let hash = sha1.final()
        let result = [UInt8](hash)
        let expected: [UInt8] = [0x2f, 0xd4, 0xe1, 0xc6,
                                 0x7a, 0x2d, 0x28, 0xfc,
                                 0xed, 0x84, 0x9e, 0xe1,
                                 0xbb, 0x76, 0xe7, 0x39,
                                 0x1b, 0x93, 0xeb, 0x12]
        assertEqual(result, expected)
    }

    func testSHA1String() {
        let bytes = [UInt8]("The quick brown fox jumps over the lazy dog".utf8)
        var sha1 = SHA1()
        sha1.update(bytes)
        let hash = sha1.final()
        let result = String(hash)
        let expected = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        assertEqual(result, expected)
    }

    func testSHA1ArrayExtension() {
        let bytes = [UInt8]("The quick brown fox jumps over the lazy dog".utf8)
        let result = bytes.sha1()
        let expected: [UInt8] = [0x2f, 0xd4, 0xe1, 0xc6,
                                 0x7a, 0x2d, 0x28, 0xfc,
                                 0xed, 0x84, 0x9e, 0xe1,
                                 0xbb, 0x76, 0xe7, 0x39,
                                 0x1b, 0x93, 0xeb, 0x12]
        assertEqual(result, expected)
    }
}
