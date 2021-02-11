import ASN1

public struct OCSP {
    public struct Response: Equatable {
        public enum Status: UInt8 {
            case success = 0x00 // Response has valid confirmations
            case malformedRequest = 0x01 // Illegal confirmation request
            case internalError = 0x02 // Internal error in issuer
            case tryLater = 0x03 // Try again later
            case sigRequired = 0x05 // Must sign the request
            case unauthorized = 0x06 // Request unauthorized
        }

        public let status: Status
        // TODO: find out is there other types
        public let basic: Basic?

        public struct Basic: Equatable {
            let value: ASN1
        }
    }
}

// MARK: Coding - https://tools.ietf.org/html/rfc6960#section-4.2.1

extension OCSP.Response {
    public static func decode(from asn1: ASN1) async throws -> Self {
        guard asn1.identifier.isConstructed,
            asn1.identifier.class == .universal,
            asn1.identifier.tag == .sequence,
            case .sequence(let sequence) = asn1.content,
            sequence.count >= 2
        else {
            throw Error.invalidASN1(asn1)
        }
        let status = try Status(from: sequence[0])
        guard status == .success else {
            return .init(status: status, basic: nil)
        }

        let eoc = sequence[1]
        guard
            eoc.identifier.isConstructed,
            eoc.identifier.class == .contextSpecific,
            eoc.identifier.tag == .endOfContent,
            case .sequence(let container) = eoc.content,
            container.count == 1
        else {
            throw Error.invalidASN1(asn1)
        }

        let typeData = container[0]
        guard
            typeData.identifier.isConstructed,
            typeData.identifier.class == .universal,
            typeData.identifier.tag == .sequence,
            case .sequence(let typeDataSequence) = typeData.content,
            typeDataSequence.count == 2
        else {
            throw Error.invalidASN1(asn1)
        }

        let type = typeDataSequence[0]
        let data = typeDataSequence[1]

        guard type.identifier.isConstructed == false,
            type.identifier.class == .universal,
            let oid = type.objectIdentifierValue,
            oid == .pkix(.accessDescription(.oscp(.basicResponse)))
        else {
            throw Error.invalidASN1(asn1)
        }

        guard data.identifier.isConstructed == false,
            data.identifier.class == .universal,
            data.identifier.tag == .octetString,
            let bytes = data.dataValue
        else {
            throw Error.invalidASN1(asn1)
        }
        let basicOCSPASN1 = try await ASN1.decode(from: bytes)
        let basic = try Basic(from: basicOCSPASN1)
        return .init(status: status, basic: basic)
    }

    public func encode() -> ASN1 {
        let content: ASN1.Content
        switch basic {
        case .none:
            content = .sequence([status.encode()])
        case .some(let basic):
            content = .sequence([status.encode(), basic.encode()])
        }
        return .init(
            identifier: .init(
                isConstructed: true,
                class: .universal,
                tag: .sequence),
            content: content)
    }
}

extension OCSP.Response.Status {
    init(from asn1: ASN1) throws {
        guard asn1.identifier.isConstructed == false,
            asn1.identifier.class == .universal,
            asn1.identifier.tag == .enumerated,
            case .integer(.sane(let value)) = asn1.content,
            let rawStatus = UInt8(exactly: value),
            let status = OCSP.Response.Status(rawValue: rawStatus)
        else {
            throw Error.invalidASN1(asn1)
        }
        self = status
    }

    func encode() -> ASN1 {
        return .init(
            identifier: .init(
                isConstructed: false,
                class: .universal,
                tag: .enumerated),
            content: .integer(.sane(Int(rawValue))))
    }
}

// TODO: Decode / Encode
extension OCSP.Response.Basic {
    init(from asn1: ASN1) throws {
        self.value = asn1
    }

    func encode() -> ASN1 {
        return self.value
    }
}
