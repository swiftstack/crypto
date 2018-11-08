// https://tools.ietf.org/html/rfc4122#appendix-C

extension UUID {
    public static let dns = UUID(
        time: .init(
            low: 0x6ba7b810,
            mid: 0x9dad,
            hiWithVersion: 0x11d1),
        clock: .init(0x80b4),
        node: .init((0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8)))

    public static let url = UUID(
        time: .init(
            low: 0x6ba7b811,
            mid: 0x9dad,
            hiWithVersion: 0x11d1),
        clock: .init(0x80b4),
        node: .init((0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8)))

    public static let oid = UUID(
        time: .init(
            low: 0x6ba7b812,
            mid: 0x9dad,
            hiWithVersion: 0x11d1),
        clock: .init(0x80b4),
        node: .init((0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8)))

    public static let x500 = UUID(
        time: .init(
            low: 0x6ba7b814,
            mid: 0x9dad,
            hiWithVersion: 0x11d1),
        clock: .init(0x80b4),
        node: .init((0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8)))
}
