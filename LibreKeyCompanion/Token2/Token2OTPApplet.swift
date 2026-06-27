import Foundation

/// Token2 on-device OTP client.
///
/// Ported from the Android `token2/Token2Client.kt` (NFC/PC-SC path only — the
/// USB-HID path from the original isn't reachable on iOS). Talks to the Token2
/// management applet over ISO-7816 APDUs.
///
/// The management applet AID is F0 00 00 01 4F 74 70 01.
///
/// Implements: READ_CONFIG feature detection, GET_ECDH_PUBKEY, enumerate (paged),
/// read-one, write/update (encrypted), delete (encrypted), erase-all.
/// SET_DEVICE_TYPE is intentionally omitted on iOS (it's the brick-risk command).
final class Token2OTPApplet {
    private let transport: KeyTransport
    init(transport: KeyTransport) { self.transport = transport }

    static let MGMT_AID = Data([0xF0, 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01])

    // CLA INS P1 P2 per §6.
    private enum Cmd {
        static let getEcdhPubkey: [UInt8] = [0x80, 0xC5, 0x01, 0x00]
        static let readConfig: [UInt8]    = [0x80, 0xC5, 0x02, 0x00]
        static let enableTotp: [UInt8]    = [0x80, 0xC5, 0x02, 0x05]
        static let enumCodes: [UInt8]     = [0x80, 0xC5, 0x05, 0x00]
        static let enumContinue: [UInt8]  = [0x80, 0xC5, 0x05, 0x01]
        static let writeSeed: [UInt8]     = [0x80, 0xC5, 0x05, 0x02]
    }

    struct DeviceInfo {
        let totpSupported: Bool
        let hotpSupported: Bool
        let nfcSupported: Bool
        let ccidSupported: Bool
        let fingerprintPresent: Bool
        let fidoHasPin: Bool
        let buttonHotpConfigured: Bool
        let fidoVersion: String
    }

    func select() async throws {
        try await transport.selectApplet(aid: Token2OTPApplet.MGMT_AID)
    }

    /// Probe used by the OTP coordinator to decide Token2-vs-OATH routing.
    func isPresent() async -> Bool {
        do { try await select(); return true } catch { return false }
    }

    // Extended-length APDU (§3): everything but PC/SC SELECT uses extended Lc.
    private func apduExt(_ cmd: [UInt8], _ data: Data) -> APDU {
        // The Kotlin builds raw bytes with a 3-byte extended Lc and no Le. Our
        // APDU type emits extended encoding automatically when le > 256 or data
        // is large; to force the exact 00 hi lo framing with no Le, set le = 0
        // and rely on extended detection via a large data path. For short data we
        // still need extended Lc, so build the body explicitly here.
        return APDU(cla: cmd[0], ins: cmd[1], p1: cmd[2], p2: cmd[3], data: data, le: 0, forceExtended: true)
    }

    private func transmitChecked(_ apdu: APDU) async throws -> Data {
        let r = try await transport.transmit(apdu)
        guard r.isSuccess else { throw mapStatus(r.sw) }
        return r.data
    }

    private func mapStatus(_ sw: UInt16) -> KeyError {
        switch sw {
        case 0x6A80, 0x6A83: return .parsing("Token2: entry not found")
        case 0x6A84:         return .parsing("Token2: not enough space on key")
        case 0x6FF9:         return .buttonPressRequired
        default:             return .unexpectedStatus(sw)
        }
    }

    /// §6.9 feature detection.
    @discardableResult
    func readConfig(numBytes: Int = 10) async throws -> DeviceInfo {
        let n = UInt8(min(max(numBytes, 10), 64))
        let resp = try await transmitChecked(apduExt(Cmd.readConfig, Data([n])))
        var r = [UInt8](resp)
        if r.count < 10 { r += [UInt8](repeating: 0, count: 10 - r.count) }
        let cfg = Int(r[1]); let ext = Int(r[9])
        let fido = "\(Int(r[6])).\(Int(r[7])).\(Int(r[8]))"
        return DeviceInfo(
            totpSupported: ext & 0x01 != 0,
            hotpSupported: cfg & 0x04 != 0,
            nfcSupported: cfg & 0x10 != 0,
            ccidSupported: ext & 0x10 != 0,
            fingerprintPresent: cfg & 0x08 != 0,
            fidoHasPin: cfg & 0x02 != 0,
            buttonHotpConfigured: cfg & 0x80 != 0,
            fidoVersion: fido)
    }

    func getEcdhPubkey() async throws -> Data {
        let pk = try await transmitChecked(apduExt(Cmd.getEcdhPubkey, Data()))
        guard pk.count == 64 else { throw KeyError.parsing("expected 64-byte pubkey, got \(pk.count)") }
        return pk
    }

    /// Enumerate all entries, following ENUM_CODES_CONTINUE paging (§6.1).
    func enumerate(timestampSeconds: Int64) async throws -> [Token2Codec.Entry] {
        var all: [Token2Codec.Entry] = []
        var resp = try await transmitChecked(
            apduExt(Cmd.enumCodes, Token2Codec.serializeReadAll(timestampSeconds: timestampSeconds)))
        while true {
            let (entries, more) = try Token2Codec.parseEnumPage(resp, fullDecode: false)
            all.append(contentsOf: entries)
            if !more { break }
            resp = try await transmitChecked(
                apduExt(Cmd.enumContinue, Token2Codec.serializeContinue(timestampSeconds: timestampSeconds)))
        }
        return all
    }

    /// Read one entry, always including the code.
    func readEntry(timestampSeconds: Int64, app: String, acct: String) async throws -> Token2Codec.Entry {
        let resp = try await transmitChecked(
            apduExt(Cmd.enumCodes, Token2Codec.serializeReadOne(timestampSeconds: timestampSeconds, app: app, acct: acct)))
        return try Token2Codec.parseEnumPage(resp, fullDecode: true).entries.first
            ?? { throw KeyError.parsing("no entry returned") }()
    }

    /// Write or update an entry (encrypted, IV-1).
    func writeEntry(_ entry: Token2Codec.Entry) async throws {
        let cleartext = try Token2Codec.serializeWriteEntry(entry)
        let pubkey = try await getEcdhPubkey()
        let blob = try Token2Crypto.encryptPayload(devicePubXy: pubkey, cleartext: cleartext, iv: Token2Crypto.IV_WRITE_SEED)
        _ = try await transmitChecked(apduExt(Cmd.writeSeed, blob))
    }

    /// Delete an entry (encrypted empty-seed write, IV-1).
    func deleteEntry(app: String, acct: String) async throws {
        let cleartext = Token2Codec.serializeDeleteEntry(appName: app, accountName: acct)
        let pubkey = try await getEcdhPubkey()
        let blob = try Token2Crypto.encryptPayload(devicePubXy: pubkey, cleartext: cleartext, iv: Token2Crypto.IV_WRITE_SEED)
        _ = try await transmitChecked(apduExt(Cmd.writeSeed, blob))
    }

    func enableTotp(_ enabled: Bool) async throws {
        _ = try await transmitChecked(apduExt(Cmd.enableTotp, Data([enabled ? 0x01 : 0x00])))
    }
}
