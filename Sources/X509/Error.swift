import ASN1

public struct Error: Swift.Error {
    public let reason: Reason
    public let source: Source
    public let context: ASN1

    init(_ reason: Reason, source: Source, context: ASN1) {
        self.reason = reason
        self.source = source
        self.context = context
    }

    public struct Source {
        public let function: String
        public let file: String
        public let line: Int

        init(_ function: String, _ file: String, _ line: Int) {
            self.function = function
            self.file = file
            self.line = line
        }
    }

    public enum Reason {
        case invalidASN1
        case unimplemented
        case innerError(Swift.Error)
    }

    static func invalidASN1(
        _ asn1: ASN1,
        _ function: String = #function,
        _ file: String = #file,
        _ line: Int = #line) -> Error
    {
        return .init(
            .invalidASN1,
            source: .init(function, file, line),
            context: asn1)
    }

    static func unimplemented(
        _ asn1: ASN1,
        _ function: String = #function,
        _ file: String = #file,
        _ line: Int = #line) -> Error
    {
        return .init(
            .unimplemented,
            source: .init(function, file, line),
            context: asn1)
    }
}

extension Error: CustomStringConvertible {
    public var description: String {
        return "\n\(source.file):\(source.line) - \(reason) - \(context)"
    }
}
