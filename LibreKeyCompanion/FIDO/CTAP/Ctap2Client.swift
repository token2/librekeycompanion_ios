import Foundation
import CryptoKit

/// A CTAP2 status code other than success (0x00).
struct CtapError: Error {
    let code: Int
    var name: String {
        switch code {
        case 0x31: return "PIN_INVALID"
        case 0x32: return "PIN_BLOCKED"
        case 0x33: return "PIN_AUTH_INVALID"
        case 0x34: return "PIN_AUTH_BLOCKED"
        case 0x35: return "PIN_NOT_SET"
        case 0x36: return "PIN_REQUIRED"
        case 0x37: return "PIN_POLICY_VIOLATION"
        case 0x3B: return "NO_CREDENTIALS"
        case 0x2B: return "KEY_STORE_FULL"
        case 0x2D: return "NOT_ALLOWED"
        case 0x2E: return "INVALID_OPTION"
        case 0x19: return "OPERATION_DENIED"
        default: return "CTAP error"
        }
    }
    var localizedDescription: String { String(format: "CTAP error 0x%02X: %@", code, name) }
}

/// CTAP2 over the NFC smart-card transport (ApduWire only — iOS has no CTAPHID).
///
/// Ported from the Android `fido/ctap/Ctap2Client.kt`, MANAGEMENT subset:
/// feature detection (getInfo), PIN retries, PIN set/change, alwaysUv, and
/// discoverable-credential (passkey) listing/deletion. It does NOT do
/// makeCredential / getAssertion. Fingerprint enrollment is omitted on iOS (it
/// needs a held multi-touch USB session).
final class Ctap2Client {
    private let transport: KeyTransport

    init(transport: KeyTransport) { self.transport = transport }

    // CTAP2 command bytes.
    private enum CMD {
        static let getInfo = 0x04
        static let clientPin = 0x06
        static let credMgmt = 0x0A
        static let credMgmtPreview = 0x41
        static let config = 0x0D
    }
    private enum SUB {           // clientPIN subcommands
        static let getRetries = 0x01
        static let getKeyAgreement = 0x02
        static let setPin = 0x03
        static let changePin = 0x04
        static let getPinToken = 0x05
        static let getUvRetries = 0x07
        static let getTokenPinPerm = 0x09
    }
    private enum CM {            // credentialManagement subcommands
        static let enumRpsBegin = 0x02
        static let enumRpsNext = 0x03
        static let enumCredsBegin = 0x04
        static let enumCredsNext = 0x05
        static let deleteCred = 0x06
    }
    private enum PERM {
        static let credMgmt = 0x04
        static let authCfg = 0x20
    }
    static let FIDO_AID = Data([0xA0,0x00,0x00,0x06,0x47,0x2F,0x00,0x01])

    func selectFido() async throws {
        try await transport.selectApplet(aid: Ctap2Client.FIDO_AID)
    }

    // ---- the ApduWire send: 80 10 00 00, body = cmd byte + CBOR ----
    private func wireSend(command: Int, data: Data) async throws -> Data {
        var payload = Data([UInt8(command)]); payload.append(data)
        let r = try await transport.transmit(APDU(cla: 0x80, ins: 0x10, p1: 0x00, p2: 0x00, data: payload, le: 256))
        guard r.isSuccess else { throw CtapError(code: 0xFF) }
        return r.data
    }

    /// Send a CTAP2 command, returning the decoded CBOR map (or empty on no body).
    @discardableResult
    private func sendCbor(_ command: Int, _ cborParams: Data?) async throws -> [Cbor.MapKey: Cbor.Value] {
        let body = try await wireSend(command: command, data: cborParams ?? Data())
        guard !body.isEmpty else { throw CtapError(code: 0xFF) }
        let status = Int(body[body.startIndex])
        if status != 0x00 { throw CtapError(code: status) }
        if body.count == 1 { return [:] }
        let decoded = try Cbor.decode(body.dropFirst())
        if case .map(let m) = decoded { return m }
        return [:]
    }

    // ---- info ----

    struct Info {
        let versions: [String]
        let options: [String: Bool]
        let pinProtocols: [Int]
        let aaguidHex: String?
        let minPinLength: Int?

        var isFido2: Bool { versions.contains { $0.hasPrefix("FIDO_2") } }
        var clientPinSet: Bool { options["clientPin"] == true }
        var alwaysUv: Bool { options["alwaysUv"] == true }
        var supportsCredMgmt: Bool { options["credMgmt"] == true || options["credentialMgmtPreview"] == true }
        var supportsConfig: Bool { options["authnrCfg"] == true }
        var supportsPinUvAuthToken: Bool { options["pinUvAuthToken"] == true }
    }

    func getInfo() async throws -> Info {
        try await selectFido()
        let m = try await sendCbor(CMD.getInfo, nil)
        let versions: [String] = {
            if case .array(let a)? = m[.int(1)] { return a.compactMap { if case .text(let s) = $0 { return s }; return nil } }
            return []
        }()
        var options: [String: Bool] = [:]
        if case .map(let om)? = m[.int(4)] {
            for (k, v) in om { if case .text(let key) = k, case .bool(let b) = v { options[key] = b } }
        }
        let protos: [Int] = {
            if case .array(let a)? = m[.int(6)] {
                return a.compactMap { if case .uint(let u) = $0 { return Int(u) }; return nil }
            }
            return [1]
        }()
        let aaguid: String? = { if case .bytes(let d)? = m[.int(3)] { return d.map { String(format: "%02x", $0) }.joined() }; return nil }()
        let minPin: Int? = { if case .uint(let u)? = m[.int(0x0D)] { return Int(u) }; return nil }()
        return Info(versions: versions, options: options, pinProtocols: protos, aaguidHex: aaguid, minPinLength: minPin)
    }

    private func protocolFor(_ info: Info) -> PinUvAuthProtocolBase {
        info.pinProtocols.contains(2) ? PinUvAuthV2() : PinUvAuthV1()
    }

    // ---- PIN retries ----

    func getPinRetries() async throws -> Int {
        let resp = try await clientPin(1, SUB.getRetries, nil)
        if case .uint(let u)? = resp[.int(3)] { return Int(u) }
        throw KeyError.parsing("no retry count in response")
    }

    private func clientPin(_ ver: Int, _ sub: Int, _ extra: [Cbor.MapKey: Cbor.Value]?) async throws -> [Cbor.MapKey: Cbor.Value] {
        var params: [Cbor.MapKey: Cbor.Value] = [.int(1): .uint(UInt64(ver)), .int(2): .uint(UInt64(sub))]
        extra?.forEach { params[$0.key] = $0.value }
        return try await sendCbor(CMD.clientPin, Cbor.encode(.map(params)))
    }

    /// Authenticator's key-agreement public key (COSE EC2) -> raw X,Y.
    private func getKeyAgreement(_ proto: PinUvAuthProtocolBase) async throws -> (Data, Data) {
        let resp = try await clientPin(proto.version, SUB.getKeyAgreement, nil)
        guard case .map(let cose)? = resp[.int(1)],
              case .bytes(let x)? = cose[.int(-2)],
              case .bytes(let y)? = cose[.int(-3)] else {
            throw KeyError.parsing("malformed keyAgreement")
        }
        return (x, y)
    }

    // ---- PIN set / change ----

    func setPin(_ newPin: String, info: Info) async throws {
        guard (4...63).contains(Data(newPin.utf8).count) else { throw KeyError.parsing("PIN must be 4..63 bytes") }
        let proto = protocolFor(info)
        let (ax, ay) = try await getKeyAgreement(proto)
        let ss = try proto.encapsulate(authX: ax, authY: ay)
        let newPinEnc = try ss.encrypt(padPin(newPin))
        let authParam = ss.authenticate(newPinEnc)
        let params: [Cbor.MapKey: Cbor.Value] = [
            .int(1): .uint(UInt64(proto.version)),
            .int(2): .uint(UInt64(SUB.setPin)),
            .int(3): .map(proto.platformCoseKey()),
            .int(4): .bytes(authParam),
            .int(5): .bytes(newPinEnc),
        ]
        try await sendCbor(CMD.clientPin, Cbor.encode(.map(params)))
    }

    func changePin(old oldPin: String, new newPin: String, info: Info) async throws {
        guard (4...63).contains(Data(newPin.utf8).count) else { throw KeyError.parsing("PIN must be 4..63 bytes") }
        let proto = protocolFor(info)
        let (ax, ay) = try await getKeyAgreement(proto)
        let ss = try proto.encapsulate(authX: ax, authY: ay)
        let pinHashLeft16 = Data(SHA256.hash(data: Data(oldPin.utf8))).prefix(16)
        let pinHashEnc = try ss.encrypt(Data(pinHashLeft16))
        let newPinEnc = try ss.encrypt(padPin(newPin))
        let authParam = ss.authenticate(newPinEnc + pinHashEnc)
        let params: [Cbor.MapKey: Cbor.Value] = [
            .int(1): .uint(UInt64(proto.version)),
            .int(2): .uint(UInt64(SUB.changePin)),
            .int(3): .map(proto.platformCoseKey()),
            .int(4): .bytes(authParam),
            .int(5): .bytes(newPinEnc),
            .int(6): .bytes(pinHashEnc),
        ]
        try await sendCbor(CMD.clientPin, Cbor.encode(.map(params)))
    }

    /// Obtain a pinUvAuthToken for follow-up commands (permission-scoped on 2.1,
    /// legacy getPinToken otherwise).
    private func getPinToken(_ pin: String, proto: PinUvAuthProtocolBase,
                             permissions: Int, supportsPermissions: Bool) async throws -> (Data, SharedSecret) {
        let (ax, ay) = try await getKeyAgreement(proto)
        let ss = try proto.encapsulate(authX: ax, authY: ay)
        let pinHashEnc = try ss.encrypt(Data(Data(SHA256.hash(data: Data(pin.utf8))).prefix(16)))
        var params: [Cbor.MapKey: Cbor.Value] = [
            .int(1): .uint(UInt64(proto.version)),
            .int(3): .map(proto.platformCoseKey()),
            .int(6): .bytes(pinHashEnc),
        ]
        if supportsPermissions {
            params[.int(2)] = .uint(UInt64(SUB.getTokenPinPerm))
            params[.int(9)] = .uint(UInt64(permissions))
        } else {
            params[.int(2)] = .uint(UInt64(SUB.getPinToken))
        }
        let resp = try await sendCbor(CMD.clientPin, Cbor.encode(.map(params)))
        guard case .bytes(let encToken)? = resp[.int(2)] else { throw KeyError.parsing("no pinUvAuthToken") }
        let token = try ss.decrypt(encToken)
        return (token, ss)
    }

    /// HMAC a message under the pinUvAuthToken (left-16 for v1, full for v2).
    private func authWithToken(_ proto: PinUvAuthProtocolBase, token: Data, msg: Data) -> Data {
        let full = PinUvAuthProtocolBase.hmacSha256(key: token, msg: msg)
        return proto.version == 1 ? Data(full.prefix(16)) : full
    }

    // ---- alwaysUv ----

    private enum CFG { static let toggleAlwaysUv = 0x02 }

    /// Toggle the alwaysUv option (requires a PIN token with acfg permission).
    func toggleAlwaysUv(pin: String) async throws {
        let info = try await getInfo()
        guard info.supportsConfig else { throw KeyError.parsing("Authenticator doesn't support authenticatorConfig") }
        let proto = protocolFor(info)
        let (token, _) = try await getPinToken(pin, proto: proto, permissions: PERM.authCfg, supportsPermissions: info.supportsPinUvAuthToken)
        // Per spec §6.11: authenticate over (32 0xff bytes || 0x0d || subCommand).
        var msg = Data(repeating: 0xFF, count: 32)
        msg.append(UInt8(CMD.config)); msg.append(UInt8(CFG.toggleAlwaysUv))
        let authParam = authWithToken(proto, token: token, msg: msg)
        let params: [Cbor.MapKey: Cbor.Value] = [
            .int(1): .uint(UInt64(CFG.toggleAlwaysUv)),
            .int(3): .uint(UInt64(proto.version)),
            .int(4): .bytes(authParam),
        ]
        try await sendCbor(CMD.config, Cbor.encode(.map(params)))
    }

    // ---- passkeys (credential management) ----

    struct Passkey {
        let rpId: String
        let userName: String?
        let userDisplayName: String?
        let credentialId: Data
        var credentialIdB64Url: String {
            credentialId.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        /// WebAuthn user handle (user.id) as hex; nil if absent.
        let userHandleHex: String?
        /// COSE key algorithm of the credential public key (e.g. -7 = ES256).
        let algorithm: Int?
        /// credProtect policy (1/2/3); nil if the authenticator doesn't report it.
        let credProtect: Int?
    }

    func listPasskeys(pin: String) async throws -> [Passkey] {
        let info = try await getInfo()
        guard info.supportsCredMgmt else { throw KeyError.parsing("Authenticator doesn't support credential management") }
        let proto = protocolFor(info)
        let (token, _) = try await getPinToken(pin, proto: proto, permissions: PERM.credMgmt, supportsPermissions: info.supportsPinUvAuthToken)
        let cmCmd = info.options["credMgmt"] == true ? CMD.credMgmt : CMD.credMgmtPreview

        var result: [Passkey] = []
        for (rpId, rpHash) in try await enumerateRps(cmCmd, proto, token) {
            for c in try await enumerateCreds(cmCmd, proto, token, rpIdHash: rpHash) {
                result.append(Passkey(rpId: rpId, userName: c.userName, userDisplayName: c.userDisplayName,
                                      credentialId: c.credentialId, userHandleHex: c.userHandleHex,
                                      algorithm: c.algorithm, credProtect: c.credProtect))
            }
        }
        return result
    }

    func deletePasskey(pin: String, credentialId: Data) async throws {
        let info = try await getInfo()
        guard info.supportsCredMgmt else { throw KeyError.parsing("Authenticator doesn't support credential management") }
        let proto = protocolFor(info)
        let (token, _) = try await getPinToken(pin, proto: proto, permissions: PERM.credMgmt, supportsPermissions: info.supportsPinUvAuthToken)
        let cmCmd = info.options["credMgmt"] == true ? CMD.credMgmt : CMD.credMgmtPreview
        let credDesc: [Cbor.MapKey: Cbor.Value] = [.text("id"): .bytes(credentialId), .text("type"): .text("public-key")]
        let subParams: [Cbor.MapKey: Cbor.Value] = [.int(2): .map(credDesc)]
        let authParam = authWithToken(proto, token: token,
                                      msg: Data([UInt8(CM.deleteCred)]) + Cbor.encode(.map(subParams)))
        let params: [Cbor.MapKey: Cbor.Value] = [
            .int(1): .uint(UInt64(CM.deleteCred)),
            .int(2): .map(subParams),
            .int(3): .uint(UInt64(proto.version)),
            .int(4): .bytes(authParam),
        ]
        try await sendCbor(cmCmd, Cbor.encode(.map(params)))
    }

    private func credMgmtAuth(_ proto: PinUvAuthProtocolBase, token: Data, sub: Int, subCbor: Data?) -> Data {
        authWithToken(proto, token: token, msg: Data([UInt8(sub)]) + (subCbor ?? Data()))
    }

    private func enumerateRps(_ cmCmd: Int, _ proto: PinUvAuthProtocolBase, _ token: Data) async throws -> [(String, Data)] {
        var out: [(String, Data)] = []
        let authParam = credMgmtAuth(proto, token: token, sub: CM.enumRpsBegin, subCbor: nil)
        let begin: [Cbor.MapKey: Cbor.Value] = [.int(1): .uint(UInt64(CM.enumRpsBegin)), .int(3): .uint(UInt64(proto.version)), .int(4): .bytes(authParam)]
        let first: [Cbor.MapKey: Cbor.Value]
        do { first = try await sendCbor(cmCmd, Cbor.encode(.map(begin))) }
        catch let e as CtapError { if e.code == 0x2E || e.code == 0x3B { return [] }; throw e }
        let total: Int = { if case .uint(let u)? = first[.int(5)] { return Int(u) }; return 0 }()
        if total == 0 { return [] }
        addRp(first, &out)
        for _ in 0..<(total - 1) {
            let r = try await sendCbor(cmCmd, Cbor.encode(.map([.int(1): .uint(UInt64(CM.enumRpsNext))])))
            addRp(r, &out)
        }
        return out
    }

    private func addRp(_ m: [Cbor.MapKey: Cbor.Value], _ out: inout [(String, Data)]) {
        guard case .map(let rp)? = m[.int(3)], case .text(let id)? = rp[.text("id")] else { return }
        let hash: Data = { if case .bytes(let h)? = m[.int(4)] { return h }; return Data() }()
        out.append((id, hash))
    }

    private func enumerateCreds(_ cmCmd: Int, _ proto: PinUvAuthProtocolBase, _ token: Data, rpIdHash: Data) async throws -> [Passkey] {
        var out: [Passkey] = []
        let subParams: [Cbor.MapKey: Cbor.Value] = [.int(1): .bytes(rpIdHash)]
        let authParam = credMgmtAuth(proto, token: token, sub: CM.enumCredsBegin, subCbor: Cbor.encode(.map(subParams)))
        let begin: [Cbor.MapKey: Cbor.Value] = [.int(1): .uint(UInt64(CM.enumCredsBegin)), .int(2): .map(subParams), .int(3): .uint(UInt64(proto.version)), .int(4): .bytes(authParam)]
        let first: [Cbor.MapKey: Cbor.Value]
        do { first = try await sendCbor(cmCmd, Cbor.encode(.map(begin))) }
        catch let e as CtapError { if e.code == 0x2E || e.code == 0x3B { return [] }; throw e }
        let total: Int = { if case .uint(let u)? = first[.int(9)] { return Int(u) }; return 0 }()
        if total == 0 { return out }
        addCred(first, &out)
        for _ in 0..<(total - 1) {
            let r = try await sendCbor(cmCmd, Cbor.encode(.map([.int(1): .uint(UInt64(CM.enumCredsNext))])))
            addCred(r, &out)
        }
        return out
    }

    private func addCred(_ m: [Cbor.MapKey: Cbor.Value], _ out: inout [Passkey]) {
        guard case .map(let credId)? = m[.int(7)], case .bytes(let id)? = credId[.text("id")] else { return }
        var userName: String?; var userDisplay: String?; var userHandle: String?
        if case .map(let user)? = m[.int(6)] {
            if case .text(let n)? = user[.text("name")] { userName = n }
            if case .text(let d)? = user[.text("displayName")] { userDisplay = d }
            if case .bytes(let h)? = user[.text("id")] { userHandle = h.map { String(format: "%02x", $0) }.joined() }
        }
        var algorithm: Int?
        if case .map(let cose)? = m[.int(8)], case .nint(let a)? = cose[.int(3)] { algorithm = Int(a) }
        var credProtect: Int?
        if case .uint(let cp)? = m[.int(0x0A)] { credProtect = Int(cp) }
        out.append(Passkey(rpId: "", userName: userName, userDisplayName: userDisplay,
                           credentialId: id, userHandleHex: userHandle,
                           algorithm: algorithm, credProtect: credProtect))
    }

    // ---- helpers ----

    private func padPin(_ pin: String) -> Data {
        let raw = Data(pin.utf8)
        let len = max(64, ((raw.count + 15) / 16) * 16)
        var padded = Data(count: len)
        padded.replaceSubrange(0..<raw.count, with: raw)
        return padded
    }
}
