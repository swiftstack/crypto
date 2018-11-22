extension String {
    func shiftingRight(by spaces: Int) -> String {
        let lines = self.split(separator: "\n")
        return lines[0] + "\n" + lines[1...]
            .map{ String(repeating: " ", count: spaces) + $0 }
            .joined(separator: "\n")
    }
}

extension ASN1: CustomStringConvertible {
    func prettyDescription(level: Int) -> String {
        return """

        .init(
            identifier: \(identifier.prettyDescription(level: level + 1)),
            content: \(content.prettyDescription(level: level + 1)))
        """.shiftingRight(by: level * 4)
    }

    public var description: String {
        return prettyDescription(level: 0)
    }
}

extension ASN1.Identifier: CustomStringConvertible {
    func prettyDescription(level: Int) -> String {
        return """

        .init(
            isConstructed: \(isConstructed),
            class: .\(`class`),
            tag: .\(tag))
        """.shiftingRight(by: level * 4)
    }

    public var description: String {
        return prettyDescription(level: 0)
    }
}

extension ASN1.Content: CustomStringConvertible {
    func prettyDescription(level: Int) -> String {
        let description: String
        switch self {
        case .boolean(let value):
            description = """
            .boolean(\(value))
            """
        case .integer(let value):
            description = """
                .integer(\(value))
                """
        case .string(let value):
            description = """
            .string(\(value))
            """
        case .data(let value):
            description = """
                .data(\(value)
                """
        case .sequence(let value):
            description = """
                .sequence(\(value))
                """
        case .objectIdentifier(let value):
            description = """
                .objectIdentifier(\(value))
                """
        }
        return description.shiftingRight(by: level * 4)
    }

    public var description: String {
        return prettyDescription(level: 0)
    }
}
