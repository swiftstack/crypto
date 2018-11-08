extension UUID {
    /// UUID version 4 (random)
    public init() {
        self.time = Time(.random(in: .min ... .max))
        self.clock = Clock(.random(in: .min ... .max))
        self.node = Node(.random(in: .min ... .max))
        self.version = .v4
    }
}
