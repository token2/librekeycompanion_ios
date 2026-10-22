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
        case 0x27: return "OPERATION_DENIED"
        case 0x30: return "NOT_ALLOWED"
        case 0x3C: return "UV_BLOCKED"
        case 0x3E: return "FP_DATABASE_FULL"
        case 0x2F: return "USER_ACTION_TIMEOUT"
        default: return "CTAP error"
        }
    }
    var localizedDescription: String { String(format: "CTAP error 0x%02X: %@", code, name) }
}

/// CTAP2 management client over a `CtapChannel` (iOS has no CTAPHID).
///
/// Ported from the Android `fido/ctap/Ctap2Client.kt`, MANAGEMENT subset:
/// feature detection (getInfo), PIN retries, PIN set/change, minimum PIN length,
/// alwaysUv, reset, discoverable-credential (passkey) listing/deletion and
/// fingerprint (bio) enrollment management. It does NOT do makeCredential /
/// getAssertion. Fingerprint *capture* needs a channel that holds the session
/// open across touches (`CtapChannel.holdsSession`).
final class Ctap2Client {
    let channel: CtapChannel

    init(channel: CtapChannel) { self.channel = channel }
    convenience init(transport: KeyTransport) { self.init(channel: StandardCtapChannel(transport: transport)) }

    // CTAP2 command bytes.
    private enum CMD {
        static let getInfo = 0x04
        static let clientPin = 0x06
        static let credMgmt = 0x0A
        static let credMgmtPreview = 0x41
        static let config = 0x0D
        static let reset = 0x07
        static let bioEnroll = 0x09
        static let bioEnrollPreview = 0x40
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
        static let bioEnroll = 0x08
        static let authCfg = 0x20
    }

    func selectFido() async throws {
        try await channel.select()
    }

    private func wireSend(command: Int, data: Data) async throws -> Data {
        try await channel.send(command: command, data: data)
    }

    /// Send a CTAP2 command, returning the decoded CBOR map (or empty on no body).
    @discardableResult
    private func sendCbor(_ command: Int, _ cborParams: Data?) async throws -> [Cbor.MapKey: Cbor.Value] {
        let body = try await wireSend(command: command, data: cborParams ?? Data())
        return try parseBody(body)
    }

    private func parseBody(_ body: Data) throws -> [Cbor.MapKey: Cbor.Value] {
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
        var supportsSetMinPinLength: Bool { options["setMinPINLength"] == true }
        /// Key has a fingerprint sensor. `bioEnroll` is false (not absent) when no
        /// finger is enrolled yet, so presence of the key is what matters.
        var supportsBioEnroll: Bool { options["bioEnroll"] != nil || options["userVerificationMgmtPreview"] != nil }
        var bioUsesPreview: Bool { options["bioEnroll"] == nil && options["userVerificationMgmtPreview"] != nil }
        var hasEnrolledFingerprint: Bool { options["bioEnroll"] == true || options["userVerificationMgmtPreview"] == true }
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

    // ---- minimum PIN length (authenticatorConfig setMinPINLength) ----

    private enum CFGSUB { static let setMinPinLength = 0x03 }

    /// Raise the minimum PIN length. With `alphanumeric` the length applies to
    /// PINs containing letters or symbols (vendor extension, needs a channel with
    /// `supportsAlphanumericMinPin`; PIN/UV auth protocol 1 is used for it).
    /// CTAP only allows the minimum to grow; lowering it needs a reset.
    func setMinPinLength(pin: String, length: Int, alphanumeric: Bool) async throws {
        guard (4...63).contains(length) else { throw KeyError.parsing("Minimum PIN length must be 4–63") }
        let info = try await getInfo()
        guard info.supportsConfig else { throw KeyError.parsing("Authenticator doesn't support authenticatorConfig") }
        if alphanumeric {
            guard channel.supportsAlphanumericMinPin else {
                throw KeyError.unsupportedOnPlatform("This key doesn't support a separate alphanumeric PIN minimum here.")
            }
        } else {
            guard info.supportsSetMinPinLength else { throw KeyError.parsing("Authenticator doesn't support setMinPINLength") }
        }
        let proto: PinUvAuthProtocolBase = alphanumeric ? PinUvAuthV1() : protocolFor(info)
        let (token, _) = try await getPinToken(pin, proto: proto, permissions: PERM.authCfg,
                                               supportsPermissions: info.supportsPinUvAuthToken)
        let subParams: [Cbor.MapKey: Cbor.Value] = [.int(1): .uint(UInt64(length))]
        let subCbor = Cbor.encode(.map(subParams))
        var msg = Data(repeating: 0xFF, count: 32)
        msg.append(UInt8(CMD.config)); msg.append(UInt8(CFGSUB.setMinPinLength)); msg.append(subCbor)
        let params: [Cbor.MapKey: Cbor.Value] = [
            .int(1): .uint(UInt64(CFGSUB.setMinPinLength)),
            .int(2): .map(subParams),
            .int(3): .uint(UInt64(proto.version)),
            .int(4): .bytes(authWithToken(proto, token: token, msg: msg)),
        ]
        let body = Cbor.encode(.map(params))
        if alphanumeric {
            var payload = Data([UInt8(CMD.config)]); payload.append(body)
            _ = try parseBody(try await channel.sendAlphanumericMinPinConfig(data: payload))
        } else {
            try await sendCbor(CMD.config, body)
        }
    }

    // ---- reset ----

    /// authenticatorReset: erases all passkeys and fingerprints and clears the
    /// PIN. Keys only accept it shortly after power-up (≈10 s) and usually want a
    /// touch; otherwise they answer NOT_ALLOWED (0x30).
    func reset() async throws {
        try await selectFido()
        try await sendCbor(CMD.reset, nil)
    }

    // ---- fingerprints (authenticatorBioEnrollment, modality 1) ----

    struct FingerprintSensorInfo {
        let fingerprintKind: Int?          // 1 touch, 2 swipe
        let maxSamplesForEnroll: Int?
        let maxFriendlyNameBytes: Int?
    }

    struct Fingerprint: Identifiable, Equatable {
        let templateId: Data
        let name: String?
        var id: Data { templateId }
    }

    struct EnrollSample {
        let templateId: Data
        let lastStatus: Int
        let remaining: Int
        var complete: Bool { remaining == 0 && lastStatus == 0 }
    }

    private enum BIO {
        static let modalityFp = 0x01
        static let enrollBegin = 0x01
        static let captureNext = 0x02
        static let cancel = 0x03
        static let enumerate = 0x04
        static let setName = 0x05
        static let remove = 0x06
        static let sensorInfo = 0x07
    }

    private func bioCmd(_ info: Info) -> Int { info.bioUsesPreview ? CMD.bioEnrollPreview : CMD.bioEnroll }

    private func bioAuth(_ proto: PinUvAuthProtocolBase, token: Data, sub: Int, subCbor: Data?) -> Data {
        authWithToken(proto, token: token, msg: Data([UInt8(BIO.modalityFp), UInt8(sub)]) + (subCbor ?? Data()))
    }

    private func bioInfo() async throws -> Info {
        let info = try await getInfo()
        guard info.supportsBioEnroll else { throw KeyError.parsing("This key has no fingerprint sensor") }
        return info
    }

    func fingerprintSensorInfo() async throws -> FingerprintSensorInfo {
        let info = try await bioInfo()
        let params: [Cbor.MapKey: Cbor.Value] = [.int(1): .uint(UInt64(BIO.modalityFp)), .int(2): .uint(UInt64(BIO.sensorInfo))]
        let r = try await sendCbor(bioCmd(info), Cbor.encode(.map(params)))
        func int(_ k: Int) -> Int? { if case .uint(let u)? = r[.int(k)] { return Int(u) }; return nil }
        return FingerprintSensorInfo(fingerprintKind: int(2), maxSamplesForEnroll: int(3), maxFriendlyNameBytes: int(8))
    }

    /// An authorised bio session: one PIN token reused for every call in it, so a
    /// whole enrollment (begin, captures, name) needs the PIN only once.
    final class BioSession {
        fileprivate let client: Ctap2Client
        fileprivate let info: Info
        fileprivate let proto: PinUvAuthProtocolBase
        fileprivate let token: Data
        fileprivate init(client: Ctap2Client, info: Info, proto: PinUvAuthProtocolBase, token: Data) {
            self.client = client; self.info = info; self.proto = proto; self.token = token
        }

        func list() async throws -> [Fingerprint] { try await client.bioList(self) }
        func rename(templateId: Data, name: String) async throws { try await client.bioRename(self, templateId: templateId, name: name) }
        func remove(templateId: Data) async throws { try await client.bioRemove(self, templateId: templateId) }
        func enrollBegin(timeoutMs: Int = 10_000) async throws -> EnrollSample { try await client.bioEnrollBegin(self, timeoutMs: timeoutMs) }
        func captureNext(templateId: Data, timeoutMs: Int = 10_000) async throws -> EnrollSample {
            try await client.bioCaptureNext(self, templateId: templateId, timeoutMs: timeoutMs)
        }
        func cancelEnrollment() async { await client.bioCancel(self) }
    }

    func bioSession(pin: String) async throws -> BioSession {
        let info = try await bioInfo()
        let proto = protocolFor(info)
        let (token, _) = try await getPinToken(pin, proto: proto, permissions: PERM.bioEnroll,
                                               supportsPermissions: info.supportsPinUvAuthToken)
        return BioSession(client: self, info: info, proto: proto, token: token)
    }

    private func bioSend(_ s: BioSession, sub: Int, subParams: [Cbor.MapKey: Cbor.Value]?) async throws -> [Cbor.MapKey: Cbor.Value] {
        let subCbor = subParams.map { Cbor.encode(.map($0)) }
        var params: [Cbor.MapKey: Cbor.Value] = [
            .int(1): .uint(UInt64(BIO.modalityFp)),
            .int(2): .uint(UInt64(sub)),
            .int(4): .uint(UInt64(s.proto.version)),
            .int(5): .bytes(bioAuth(s.proto, token: s.token, sub: sub, subCbor: subCbor)),
        ]
        if let subParams { params[.int(3)] = .map(subParams) }
        return try await sendCbor(bioCmd(s.info), Cbor.encode(.map(params)))
    }

    fileprivate func bioList(_ s: BioSession) async throws -> [Fingerprint] {
        let r: [Cbor.MapKey: Cbor.Value]
        do { r = try await bioSend(s, sub: BIO.enumerate, subParams: nil) }
        catch let e as CtapError { if e.code == 0x2E || e.code == 0x3B { return [] }; throw e }
        guard case .array(let list)? = r[.int(7)] else { return [] }
        return list.compactMap { v in
            guard case .map(let m) = v, case .bytes(let id)? = m[.int(1)] else { return nil }
            var name: String?
            if case .text(let n)? = m[.int(2)] { name = n }
            return Fingerprint(templateId: id, name: name)
        }
    }

    fileprivate func bioRename(_ s: BioSession, templateId: Data, name: String) async throws {
        _ = try await bioSend(s, sub: BIO.setName, subParams: [.int(1): .bytes(templateId), .int(2): .text(name)])
    }

    fileprivate func bioRemove(_ s: BioSession, templateId: Data) async throws {
        _ = try await bioSend(s, sub: BIO.remove, subParams: [.int(1): .bytes(templateId)])
    }

    private func sample(_ r: [Cbor.MapKey: Cbor.Value], templateId: Data) -> EnrollSample {
        func int(_ k: Int) -> Int { if case .uint(let u)? = r[.int(k)] { return Int(u) }; return 0 }
        return EnrollSample(templateId: templateId, lastStatus: int(5), remaining: int(6))
    }

    fileprivate func bioEnrollBegin(_ s: BioSession, timeoutMs: Int) async throws -> EnrollSample {
        let r = try await bioSend(s, sub: BIO.enrollBegin, subParams: [.int(3): .uint(UInt64(timeoutMs))])
        guard case .bytes(let templateId)? = r[.int(4)] else { throw CtapError(code: 0xFF) }
        return sample(r, templateId: templateId)
    }

    fileprivate func bioCaptureNext(_ s: BioSession, templateId: Data, timeoutMs: Int) async throws -> EnrollSample {
        let r = try await bioSend(s, sub: BIO.captureNext,
                                  subParams: [.int(1): .bytes(templateId), .int(3): .uint(UInt64(timeoutMs))])
        return sample(r, templateId: templateId)
    }

    fileprivate func bioCancel(_ s: BioSession) async {
        let params: [Cbor.MapKey: Cbor.Value] = [.int(1): .uint(UInt64(BIO.modalityFp)), .int(2): .uint(UInt64(BIO.cancel))]
        _ = try? await sendCbor(bioCmd(s.info), Cbor.encode(.map(params)))
    }

    /// Plain-language text for lastEnrollSampleStatus (CTAP 2.1 §6.7.2).
    static func sampleStatusText(_ code: Int) -> String {
        switch code {
        case 0x00: return "Good sample"
        case 0x01: return "Too high — centre your finger"
        case 0x02: return "Too low — centre your finger"
        case 0x03: return "Too far left — centre your finger"
        case 0x04: return "Too far right — centre your finger"
        case 0x05: return "Too fast — hold still"
        case 0x06: return "Too slow"
        case 0x07: return "Poor quality — clean your finger and the sensor"
        case 0x08: return "Too skewed — straighten your finger"
        case 0x09: return "Too short — cover more of the sensor"
        case 0x0A: return "Merge failure — try again"
        case 0x0B: return "This fingerprint is already enrolled"
        case 0x0D: return "No touch detected"
        case 0x0E: return "Lift your finger and touch again"
        default: return "Touch the sensor again"
        }
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
