import Foundation

/// A credential stored on the YKOATH applet.
public struct OATHCredential: Identifiable, Hashable {
    public let id: String          // full YKOATH name, e.g. "issuer:account"
    public let issuer: String?
    public let account: String
    public let kind: OATHKind
    public let algorithm: OATHAlgorithm
    public let digits: Int

    public init(name: String, kind: OATHKind, algorithm: OATHAlgorithm, digits: Int) {
        self.id = name
        self.kind = kind
        self.algorithm = algorithm
        self.digits = digits
        if let r = name.range(of: ":") {
            self.issuer = String(name[..<r.lowerBound])
            self.account = String(name[r.upperBound...])
        } else {
            self.issuer = nil
            self.account = name
        }
    }
}

/// A computed code plus its validity window.
public struct OATHCode {
    public let value: String
    public let secondsRemaining: Int
}

/// Client for the YKOATH applet (the OATH protocol used by YubiKey-class keys).
///
/// Ported from the Android `oath/` applet code. Talks ISO-7816 APDUs through any
/// `KeyTransport`; on iOS that is always `NFCTransport`.
public final class YKOATHApplet {
    private let transport: KeyTransport

    // YKOATH instruction set.
    private enum INS {
        static let put: UInt8 = 0x01
        static let delete: UInt8 = 0x02
        static let reset: UInt8 = 0x04
        static let list: UInt8 = 0xA1
        static let calculate: UInt8 = 0xA2
        static let calculateAll: UInt8 = 0xA4
    }
    // TLV tags used by the applet.
    private enum Tag {
        static let name: UInt8 = 0x71
        static let key: UInt8 = 0x73
        static let challenge: UInt8 = 0x74
        static let responseFull: UInt8 = 0x75
        static let responseTrunc: UInt8 = 0x76
        static let property: UInt8 = 0x78
        static let listEntry: UInt8 = 0x72
        static let imf: UInt8 = 0x7A          // initial moving factor (HOTP counter)
    }
    // Property byte flags (tag 0x78).
    private enum Property {
        static let requireTouch: UInt8 = 0x02
    }

    public init(transport: KeyTransport) { self.transport = transport }

    /// SELECT the OATH applet. Call once per session before other operations.
    public func select() async throws {
        try await transport.selectApplet(aid: Data([0xA0,0x00,0x00,0x05,0x27,0x21,0x01]))
    }

    /// LIST all credential names and their type/algorithm metadata.
    public func list() async throws -> [OATHCredential] {
        let resp = try await transport.transmit(
            APDU(cla: 0x00, ins: INS.list, p1: 0x00, p2: 0x00, le: 256))
        guard resp.isSuccess else { throw KeyError.unexpectedStatus(resp.sw) }

        var creds: [OATHCredential] = []
        for tlv in TLV.parse(resp.data) where tlv.tag == Tag.listEntry {
            // First byte packs algorithm (low nibble) and type (high nibble).
            guard tlv.value.count >= 1 else { continue }
            let typeAlgo = tlv.value[0]
            let name = String(decoding: tlv.value.dropFirst(), as: UTF8.self)
            let kind: OATHKind = (typeAlgo & 0xF0) == OATHKind.hotp.ykoathCode ? .hotp : .totp
            let algo: OATHAlgorithm = {
                switch typeAlgo & 0x0F {
                case OATHAlgorithm.sha256.ykoathCode: return .sha256
                case OATHAlgorithm.sha512.ykoathCode: return .sha512
                default: return .sha1
                }
            }()
            creds.append(OATHCredential(name: name, kind: kind, algorithm: algo, digits: 6))
        }
        return creds
    }

    /// CALCULATE one credential. For TOTP the challenge is the time counter.
    public func calculate(_ cred: OATHCredential,
                          time: TimeInterval = Date().timeIntervalSince1970,
                          step: TimeInterval = 30) async throws -> OATHCode {
        var data = Data()
        data.append(TLV.encode(tag: Tag.name, value: Data(cred.id.utf8)))

        var challenge = Data(count: 8)
        if cred.kind == .totp {
            let counter = UInt64(time / step).bigEndian
            challenge = withUnsafeBytes(of: counter) { Data($0) }
        }
        data.append(TLV.encode(tag: Tag.challenge, value: challenge))

        // P2 = 0x01 requests a truncated response.
        let resp = try await transport.transmit(
            APDU(cla: 0x00, ins: INS.calculate, p1: 0x00, p2: 0x01, data: data, le: 256))
        guard resp.isSuccess else { throw KeyError.unexpectedStatus(resp.sw) }

        guard let tlv = TLV.parse(resp.data).first(where: { $0.tag == Tag.responseTrunc }),
              tlv.value.count >= 5 else {
            throw KeyError.parsing("Missing truncated response TLV.")
        }
        let digits = Int(tlv.value[0])
        let raw = tlv.value.dropFirst()
        let num = raw.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } & 0x7FFF_FFFF
        let mod = UInt32(pow(10.0, Double(digits)))
        let code = String(format: "%0\(digits)u", num % mod)
        return OATHCode(value: code, secondsRemaining: OATHCore.secondsRemaining(time: time, step: step))
    }

    /// PUT a new credential from an otpauth:// URI.
    ///
    /// Encodes, in YKOATH order: name (0x71), key (0x73), optional property byte
    /// (0x78) for touch-required, and — for HOTP — the initial moving factor
    /// (0x7A) carrying the URI's `counter` as a 4-byte big-endian value.
    public func put(_ entry: OTPAuthURI, requireTouch: Bool = false) async throws {
        var key = Data([ (entry.kind.ykoathCode | entry.algorithm.ykoathCode),
                         UInt8(entry.digits) ])
        key.append(entry.secret)

        var data = Data()
        data.append(TLV.encode(tag: Tag.name, value: Data(entry.label.utf8)))
        data.append(TLV.encode(tag: Tag.key, value: key))

        if requireTouch {
            // The property byte is sent as a bare tag+byte, not a length-prefixed TLV.
            data.append(Tag.property)
            data.append(Property.requireTouch)
        }

        if entry.kind == .hotp {
            var be = UInt32(truncatingIfNeeded: entry.counter).bigEndian
            let counterBytes = withUnsafeBytes(of: &be) { Data($0) }
            data.append(TLV.encode(tag: Tag.imf, value: counterBytes))
        }

        let resp = try await transport.transmit(
            APDU(cla: 0x00, ins: INS.put, p1: 0x00, p2: 0x00, data: data, le: 0))
        guard resp.isSuccess else { throw KeyError.unexpectedStatus(resp.sw) }
    }

    /// DELETE a credential by name.
    public func delete(_ cred: OATHCredential) async throws {
        let data = TLV.encode(tag: Tag.name, value: Data(cred.id.utf8))
        let resp = try await transport.transmit(
            APDU(cla: 0x00, ins: INS.delete, p1: 0x00, p2: 0x00, data: data, le: 0))
        guard resp.isSuccess else { throw KeyError.unexpectedStatus(resp.sw) }
    }
}
