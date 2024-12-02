import Testing

func fail(
    _ comment: @autoclosure () -> Testing.Comment? = nil,
    sourceLocation: Testing.SourceLocation = #_sourceLocation
) {
    #expect(Bool(false), comment())
}
