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
        // OTP PIN / privacy protection (R3.4+).
        static let readOtpPinFlag: [UInt8]       = [0x80, 0xC5, 0x05, 0x04]
        static let setOtpPin: [UInt8]            = [0x80, 0xC5, 0x05, 0x05]
        static let verifyOtpPin: [UInt8]         = [0x80, 0xC5, 0x05, 0x06]
        static let changeOtpPin: [UInt8]         = [0x80, 0xC5, 0x05, 0x08]
        static let readAgreementPubkey: [UInt8]  = [0x80, 0xC5, 0x05, 0x09]
    }
    private enum PinFlagLc {
        static let base: UInt8 = 0x04       // status only
        static let challenge: UInt8 = 0x29  // status + verify challenge (IV||EncRand)
        static let prime: UInt8 = 0x09      // "prime" read before the handshake
    }

    /// Set after a successful verifyOtpPin: on a protected key, enumerate/read
    /// responses come back encrypted (IV || EncData || Auth) under these keys and
    /// must be decrypted before parsing. Also selects the protected-write format.
    private var pinSession: Token2PinCrypto.SessionKeys?

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
        // 6982 = security status not satisfied. On a PIN-protected key an ordinary
        // read returns this until the verify window is open — surface it so the UI
        // can prompt to unlock.
        case 0x6982:         return .otpPinNotVerified
        case 0x6983:         return .otpPinBlocked
        default:             return .unexpectedStatus(sw)
        }
    }

    /// Transmit and return the raw response WITHOUT throwing on a non-9000 SW —
    /// PIN commands must inspect status words (6982/6983/6A81/6A86/63xx).
    private func transmitRaw(_ apdu: APDU) async throws -> APDUResponse {
        try await transport.transmit(apdu)
    }

    /// Map a PIN-command status word to a typed error (or return on success).
    private func checkPin(_ sw: UInt16) throws {
        switch sw {
        case 0x9000, 0x6100, 0x6101: return
        case 0x6982: throw KeyError.otpPinNotVerified
        case 0x6983: throw KeyError.otpPinBlocked
        case 0x6A81: throw KeyError.otpPinWrongState
        case 0x6A86, 0x6AF8: throw KeyError.otpPinUnsupported(sw)
        default:
            // 63xx = verification failed (low nibble often = retries left) → wrong PIN.
            if (sw & 0xFF00) == 0x6300 { throw KeyError.otpPinNotVerified }
            if (sw & 0xFF00) == 0x6100 { return }
            throw KeyError.unexpectedStatus(sw)
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
        var resp = maybeDecryptPage(try await transmitChecked(
            apduExt(Cmd.enumCodes, Token2Codec.serializeReadAll(timestampSeconds: timestampSeconds))))
        do {
            while true {
                let (entries, more) = try Token2Codec.parseEnumPage(resp, fullDecode: false)
                all.append(contentsOf: entries)
                if !more { break }
                resp = maybeDecryptPage(try await transmitChecked(
                    apduExt(Cmd.enumContinue, Token2Codec.serializeContinue(timestampSeconds: timestampSeconds))))
            }
        } catch {
            // If parsing failed with no active PIN session, the key likely returned
            // an encrypted page from a still-open window we don't hold keys for.
            // Surface as needs-verify instead of crashing on garbage.
            if pinSession == nil { throw KeyError.otpPinNotVerified }
            throw error
        }
        return all
    }

    /// On a PIN-protected key (after verifyOtpPin) enumerate/read responses arrive
    /// as IV(16) || EncData || Auth(16) under the session keys. Decrypt + MAC-check;
    /// otherwise pass through unchanged.
    private func maybeDecryptPage(_ data: Data) -> Data {
        guard let keys = pinSession, data.count >= 48 else { return data }
        let iv = data.prefix(16)
        let enc = data.dropFirst(16).dropLast(16)
        let auth = data.suffix(16)
        guard Token2PinCrypto.verifyAuthTag(macKey: keys.mac, data: Data(enc), tag: Data(auth)) else {
            return data   // not our encrypted page (or MAC mismatch) — let parser decide
        }
        return (try? Token2PinCrypto.sessionDecrypt(key: keys.enc, iv: Data(iv), ciphertext: Data(enc))) ?? data
    }

    /// Read one entry, always including the code.
    func readEntry(timestampSeconds: Int64, app: String, acct: String) async throws -> Token2Codec.Entry {
        let resp = try await transmitChecked(
            apduExt(Cmd.enumCodes, Token2Codec.serializeReadOne(timestampSeconds: timestampSeconds, app: app, acct: acct)))
        return try Token2Codec.parseEnumPage(resp, fullDecode: true).entries.first
            ?? { throw KeyError.parsing("no entry returned") }()
    }

    /// Seal a write cleartext, choosing format by PIN state (matches the reference
    /// `seal`): if a verify window is open the device rejects GET_ECDH_PUBKEY with
    /// 6A81, so reuse the session keys in the authenticated protected-write format;
    /// otherwise build the standard ephemeral-ECDH seed blob.
    private func sealWrite(_ cleartext: Data) async throws -> Data {
        if let keys = pinSession {
            return try Token2PinCrypto.buildProtectedWriteData(keys, cleartext: cleartext)
        }
        let pubkey = try await getEcdhPubkey()
        return try Token2Crypto.encryptPayload(devicePubXy: pubkey, cleartext: cleartext, iv: Token2Crypto.IV_WRITE_SEED)
    }

    /// Write or update an entry (encrypted, IV-1; protected format when PIN-verified).
    func writeEntry(_ entry: Token2Codec.Entry) async throws {
        let cleartext = try Token2Codec.serializeWriteEntry(entry)
        _ = try await transmitChecked(apduExt(Cmd.writeSeed, try await sealWrite(cleartext)))
    }

    /// Delete an entry (encrypted empty-seed write, IV-1; protected when PIN-verified).
    func deleteEntry(app: String, acct: String) async throws {
        let cleartext = Token2Codec.serializeDeleteEntry(appName: app, accountName: acct)
        _ = try await transmitChecked(apduExt(Cmd.writeSeed, try await sealWrite(cleartext)))
    }

    func enableTotp(_ enabled: Bool) async throws {
        _ = try await transmitChecked(apduExt(Cmd.enableTotp, Data([enabled ? 0x01 : 0x00])))
    }

    // MARK: - OTP PIN (privacy protection, firmware R3.4+)

    /// Parsed READ_OTP_PIN_FLAG head, plus the optional verify challenge.
    struct PinFlag {
        let algId: Int
        let retriesLeft: Int
        let pinLen: Int
        let maxRetries: Int
        /// (IV, EncRand), present only on the Lc=0x29 read.
        let challenge: (iv: Data, encRand: Data)?
        var isSet: Bool { pinLen > 0 }
    }

    /// The flag read is NOT a bare case-2 command: it is `header || lc || lc*0x00`
    /// (the Lc byte followed by a zero-body placeholder), short-form Lc. A bodyless
    /// read is rejected with the proprietary 6AF8.
    private func readPinFlagAPDU(_ lc: UInt8) -> APDU {
        let body = Data(repeating: 0x00, count: Int(lc))
        return APDU(cla: Cmd.readOtpPinFlag[0], ins: Cmd.readOtpPinFlag[1],
                    p1: Cmd.readOtpPinFlag[2], p2: Cmd.readOtpPinFlag[3],
                    data: body, le: 0, forceExtended: false)
    }

    private func parsePinFlag(_ data: Data) -> PinFlag {
        func at(_ i: Int) -> Int { i < data.count ? Int(data[data.startIndex + i]) : 0 }
        let challenge: (Data, Data)? = data.count >= 41
            ? (Data(data[data.startIndex+9  ..< data.startIndex+25]),
               Data(data[data.startIndex+25 ..< data.startIndex+41]))
            : nil
        return PinFlag(algId: at(0), retriesLeft: at(1), pinLen: at(2), maxRetries: at(3),
                       challenge: challenge)
    }

    /// PIN command with extended Lc (the reference build_apdu form).
    private func pinAPDU(_ cmd: [UInt8], _ data: Data) -> APDU {
        APDU(cla: cmd[0], ins: cmd[1], p1: cmd[2], p2: cmd[3], data: data, le: 0, forceExtended: true)
    }

    /// READ_OTP_PIN_FLAG status. Uses Lc=0x09 (the form the reference's working
    /// trace uses) for a reliable full head; the short Lc=0x04 read can come back
    /// truncated on some firmware, making a set PIN look unset.
    func pinStatus() async throws -> PinFlag {
        let r = try await transmitRaw(readPinFlagAPDU(PinFlagLc.prime))
        try checkPin(r.sw)
        return parsePinFlag(r.data)
    }

    /// Establish an authenticated ECDH session (returns nothing; keys held on self
    /// only after verify). Sequence: a "prime" flag read (Lc=0x09) FIRST — skipping
    /// it makes a later SET fail with 6985 — then READ_AGREEMENT_PUBKEY with the
    /// host pubkey; response = devPub(64) || sig(132). The P-521 device signature is
    /// NOT verified (matches the reference; confidentiality holds).
    private func openPinSession() async throws -> Token2PinCrypto.SessionKeys {
        let prime = try await transmitRaw(readPinFlagAPDU(PinFlagLc.prime))
        try checkPin(prime.sw)

        let hs = Token2PinCrypto.beginHandshake()
        let r = try await transmitRaw(pinAPDU(Cmd.readAgreementPubkey, hs.hostPubXy))
        try checkPin(r.sw)
        guard r.data.count >= 64 else { throw KeyError.unexpectedStatus(r.sw) }
        let devXy = Data(r.data.prefix(64))
        return try hs.derive(deviceAgreementXy: devXy)
    }

    func setOtpPin(_ pin: Data) async throws {
        let keys = try await openPinSession()
        let data = try Token2PinCrypto.buildSetPinData(keys, pin: pin)
        let r = try await transmitRaw(pinAPDU(Cmd.setOtpPin, data))
        try checkPin(r.sw)
    }

    /// VERIFY_OTP_PIN — opens the read window for this connection and retains the
    /// session keys so protected pages can be decrypted.
    func verifyOtpPin(_ pin: Data) async throws {
        let keys = try await openPinSession()
        let flagResp = try await transmitRaw(readPinFlagAPDU(PinFlagLc.challenge))
        try checkPin(flagResp.sw)
        let flag = parsePinFlag(flagResp.data)
        guard let ch = flag.challenge else { throw KeyError.unexpectedStatus(flagResp.sw) }
        let rand = try Token2PinCrypto.sessionDecryptRaw(key: keys.enc, iv: ch.iv, ciphertext: ch.encRand)
        guard rand.count == 16 else { throw KeyError.unexpectedStatus(flagResp.sw) }
        let proof = try Token2PinCrypto.buildVerifyPinData(keys, pin: pin, rand: rand)
        let r = try await transmitRaw(pinAPDU(Cmd.verifyOtpPin, proof))
        try checkPin(r.sw)
        pinSession = keys
    }

    /// CHANGE_OTP_PIN (empty newPin = remove). Requires the current PIN.
    func changeOtpPin(current: Data, new: Data) async throws {
        let keys = try await openPinSession()
        let flagResp = try await transmitRaw(readPinFlagAPDU(PinFlagLc.challenge))
        try checkPin(flagResp.sw)
        let data = try Token2PinCrypto.buildChangePinData(keys, newPin: new, currentPin: current)
        let r = try await transmitRaw(pinAPDU(Cmd.changeOtpPin, data))
        try checkPin(r.sw)
        pinSession = nil
    }

    func removeOtpPin(current: Data) async throws {
        try await changeOtpPin(current: current, new: Data())
    }

    /// Close the device's read/write window: VERIFY header + single 0x00 body
    /// (80 C5 05 06 01 00), short-form Lc. Drops our session keys too.
    func lockOtpPin() async throws {
        pinSession = nil
        let apdu = APDU(cla: Cmd.verifyOtpPin[0], ins: Cmd.verifyOtpPin[1],
                        p1: Cmd.verifyOtpPin[2], p2: Cmd.verifyOtpPin[3],
                        data: Data([0x00]), le: 0, forceExtended: false)
        _ = try? await transmitRaw(apdu)
    }

    /// Whether a verify window is currently held on this applet instance.
    var isPinVerified: Bool { pinSession != nil }
}
