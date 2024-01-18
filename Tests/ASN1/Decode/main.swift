import Test

@testable import ASN1

test("UniversalSequence") {
    let identifier = try await ASN1.Identifier.decode(from: [0x30])
    expect(identifier.isConstructed == true)
    expect(identifier.class == .universal)
    expect(identifier.tag == .sequence)
}

test("ContextSpecificEndOfContent") {
    let identifier = try await ASN1.Identifier.decode(from: [0xa0])
    expect(identifier.isConstructed == true)
    expect(identifier.class == .contextSpecific)
    expect(identifier.tag == .endOfContent)
}

test("ContentBoolean") {
    let asn1f = try await ASN1.decode(from: [0x01, 0x01, 0x00])
    let asn1t = try await ASN1.decode(from: [0x01, 0x01, 0xFF])
    expect(asn1f.identifier == .init(
        isConstructed: false,
        class: .universal,
        tag: .boolean))
    expect(asn1t.identifier == .init(
        isConstructed: false,
        class: .universal,
        tag: .boolean))
    expect(asn1f.content == .boolean(false))
    expect(asn1t.content == .boolean(true))
}

test("ContentEnumerated") {
    let result = try await ASN1.decode(from: [0x0a, 0x01, 0x00])
    expect(result.identifier == .init(
        isConstructed: false,
        class: .universal,
        tag: .enumerated))
    expect(result.content == .integer(.sane(0)))
}

test("ContentData") {
    let result = try await ASN1.decode(from: [
            0x17, 0x0d,
            0x31, 0x36, 0x30, 0x35, 0x31, 0x33,
            0x31, 0x32, 0x31, 0x39, 0x31, 0x35, 0x5a])
    expect(result.identifier == .init(
        isConstructed: false,
        class: .universal,
        tag: .utcTime))
    expect(result.content == .data([
        0x31, 0x36, 0x30, 0x35, 0x31, 0x33,
        0x31, 0x32, 0x31, 0x39, 0x31, 0x35, 0x5a]))
}

test("ContentSequence") {
    let result = try await ASN1.decode(from: [
        0x30, 0x06,
        0x0a, 0x01, 0x00,
        0x0a, 0x01, 0x00
    ])
    expect(result.identifier == .init(
        isConstructed: true,
        class: .universal,
        tag: .sequence))
    expect(result.content == .sequence([
        .init(
            identifier: .init(
                isConstructed: false,
                class: .universal,
                tag: .enumerated),
            content: .integer(.sane(0))),
        .init(
            identifier: .init(
                isConstructed: false,
                class: .universal,
                tag: .enumerated),
            content: .integer(.sane(0)))
    ]))
}

test("ContentPrintableString") {
    let result = try await ASN1.decode(from: [
        0x13, 0x02, 0x52, 0x55
    ])
    expect(result.identifier == .init(
        isConstructed: false,
        class: .universal,
        tag: .printableString))
    expect(result.content == .string("RU"))
}

test("ContentUTF8String") {
    let result = try await ASN1.decode(from: [
        0x0c, 0x19,
        0x43, 0x65, 0x72, 0x74, 0x75, 0x6d, 0x20, 0x56,
        0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
        0x65
    ])
    expect(result.identifier == .init(
        isConstructed: false,
        class: .universal,
        tag: .utf8String))
    expect(result.content == .string("Certum Validation Service"))
}

test("ContentObjectIdentifier") {
    let result = try await ASN1.decode(from: [
            0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])

    expect(result.identifier ==  .init(
        isConstructed: false,
        class: .universal,
        tag: .objectIdentifier))

    expect(result.content == .objectIdentifier(.sha256WithRSAEncryption))
}

await run()
