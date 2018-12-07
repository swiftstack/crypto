import ASN1
import Stream

public struct EDIPartyName: Equatable {
    let nameAssigner: DirectoryString?
    let partyName: DirectoryString
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.6

extension EDIPartyName {
    // EDIPartyName ::= SEQUENCE {
    //   nameAssigner            [0]     DirectoryString OPTIONAL,
    //   partyName               [1]     DirectoryString }
    public init(from asn1: ASN1) throws {
        guard let sequence = asn1.sequenceValue,
            (sequence.count == 1 || sequence.count == 2) else
        {
            throw X509.Error.invalidASN1(asn1, in: .ediPartyName(.format))
        }

        switch sequence.count {
        case 1:
            self.nameAssigner = nil
            self.partyName = try .init(from: sequence[0])
        case 2:
            self.nameAssigner = try .init(from: sequence[0])
            self.partyName = try .init(from: sequence[1])
        default:
            fatalError("unreachable")
        }
    }
}

// MARK: Error

extension EDIPartyName {
    public enum Error {
        public enum Origin {
            case format
        }
    }
}
