import Foundation

/// Token2 on-device OTP — data model + codec layer (pure functions, no I/O).
///
/// Ported from the Android `token2/Token2Codec.kt`. Implements the entry record
/// format and command payload serialization from the Token2 OTP SDK protocol.
/// The parser and serializers are validated against the spec §10.1/§10.2 worked
/// traces in `Token2CodecTests`.
///
/// NOTE on the spec's §10.1 example: its leading byte is printed `00` but
/// annotated as a TOTP entry (type 01). The normative prose (§6.1, §11) is the
/// authority: bit 7 of the first byte is the partial-page flag; bits 0–6 are the
/// first entry's `type`; the trailing OTP-code field is present ONLY when
/// `type == TOTP && button == not_required`.
enum Token2Codec {

    static let TYPE_HOTP = 0x00
    static let TYPE_TOTP = 0x01
    static let ALG_SHA1 = 0xC1
    static let ALG_SHA256 = 0xC2

    struct Entry: Hashable {
        let type: Int
        let algorithm: Int
        let timestep: Int
        let codeLength: Int
        let buttonRequired: Bool
        let appName: String
        let accountName: String
        var otpCode: String? = nil
        var seed: Data? = nil          // only set on writes; never returned by device

        var isTotp: Bool { type == TYPE_TOTP }

        // Identity is (app, account) — matches the Kotlin equals/hashCode.
        static func == (l: Entry, r: Entry) -> Bool {
            l.type == r.type && l.appName == r.appName && l.accountName == r.accountName
        }
        func hash(into h: inout Hasher) {
            h.combine(appName); h.combine(accountName)
        }
    }

    struct ParseError: Error { let message: String }

    /// Parse one ENUM_CODES response page. Bit 7 of the first byte is the
    /// partial-page flag; bits 0–6 are the first entry's type. Returns the
    /// entries plus whether more pages follow (issue ENUM_CODES_CONTINUE).
    static func parseEnumPage(_ data: Data, fullDecode: Bool = false) throws -> (entries: [Entry], more: Bool) {
        if data.isEmpty { return ([], false) }
        let bytes = [UInt8](data)
        let morePages = (bytes[0] & 0x80) != 0
        var stream = bytes
        stream[0] = stream[0] & 0x7F          // clear partial flag to recover the type

        var entries: [Entry] = []
        var i = 0
        while i < stream.count {
            if i + 7 > stream.count { break }   // trailing padding shorter than a header
            let type = Int(stream[i]); i += 1
            let algo = Int(stream[i]); i += 1
            let timestep = (Int(stream[i]) << 8) | Int(stream[i + 1]); i += 2
            let codeLen = Int(stream[i]); i += 1
            let btn = Int(stream[i]); i += 1
            let appLen = Int(stream[i]); i += 1
            guard i + appLen <= stream.count else { throw ParseError(message: "app_name overruns page") }
            let app = String(bytes: stream[i..<i+appLen], encoding: .ascii) ?? ""; i += appLen
            guard i < stream.count else { throw ParseError(message: "missing account_name_len") }
            let acctLen = Int(stream[i]); i += 1
            guard i + acctLen <= stream.count else { throw ParseError(message: "account_name overruns page") }
            let acct = String(bytes: stream[i..<i+acctLen], encoding: .ascii) ?? ""; i += acctLen

            var code: String? = nil
            let hasTail = fullDecode || (type == TYPE_TOTP && btn == 0x00)
            if hasTail {
                guard i < stream.count else { throw ParseError(message: "missing otp_code_len") }
                let codeStrLen = Int(stream[i]); i += 1
                guard i + codeStrLen <= stream.count else { throw ParseError(message: "otp_code overruns page") }
                code = String(bytes: stream[i..<i+codeStrLen], encoding: .ascii); i += codeStrLen
            }
            entries.append(Entry(type: type, algorithm: algo, timestep: timestep,
                                 codeLength: codeLen, buttonRequired: btn != 0,
                                 appName: app, accountName: acct, otpCode: code))
        }
        return (entries, morePages)
    }

    /// Build the cleartext write payload (§6.3) — encrypted before sending.
    static func serializeWriteEntry(_ e: Entry) throws -> Data {
        let seed = e.seed ?? Data()
        try validateWrite(e, seed: seed)
        var out = Data()
        out.append(UInt8(e.type))
        out.append(UInt8(e.algorithm))
        out.append(UInt8((e.timestep >> 8) & 0xFF)); out.append(UInt8(e.timestep & 0xFF))
        out.append(UInt8(e.codeLength))
        out.append(e.buttonRequired ? 0x01 : 0x00)
        let app = Data(e.appName.utf8); out.append(UInt8(app.count)); out.append(app)
        let acct = Data(e.accountName.utf8); out.append(UInt8(acct.count)); out.append(acct)
        out.append(UInt8(seed.count)); out.append(seed)
        return out
    }

    /// Delete = write payload with config zeroed and an empty seed (§6.4).
    static func serializeDeleteEntry(appName: String, accountName: String) -> Data {
        var out = Data()
        out.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  // type, algo, timestep u16, codeLen, btn
        let app = Data(appName.utf8); out.append(UInt8(app.count)); out.append(app)
        let acct = Data(accountName.utf8); out.append(UInt8(acct.count)); out.append(acct)
        out.append(0x00)                                              // seed_len = 0
        return out
    }

    /// ENUM_CODES READ_ALL request: 0x03 || u64_be(timestamp) (§6.1).
    static func serializeReadAll(timestampSeconds: Int64) -> Data {
        Data([0x03]) + u64be(timestampSeconds)
    }

    /// ENUM_CODES READ_ONE request (§6.2).
    static func serializeReadOne(timestampSeconds: Int64, app: String, acct: String) -> Data {
        var out = Data()
        out.append(0x01); out.append(u64be(timestampSeconds))
        let a = Data(app.utf8); out.append(UInt8(a.count)); out.append(a)
        let b = Data(acct.utf8); out.append(UInt8(b.count)); out.append(b)
        return out
    }

    static func serializeContinue(timestampSeconds: Int64) -> Data { u64be(timestampSeconds) }

    private static func u64be(_ v: Int64) -> Data {
        var b = Data(count: 8)
        var x = UInt64(bitPattern: v)
        for i in stride(from: 7, through: 0, by: -1) {
            b[i] = UInt8(x & 0xFF); x >>= 8
        }
        return b
    }

    /// Client-side validation from §9.
    static func validateWrite(_ e: Entry, seed: Data) throws {
        func check(_ cond: Bool, _ msg: String) throws {
            if !cond { throw KeyError.parsing(msg) }
        }
        try check((1...0xFFFF).contains(e.timestep), "timestep must be 1..65535")
        try check((4...10).contains(e.codeLength), "code_length must be 4..10")
        try check((0...64).contains(Data(e.appName.utf8).count), "app_name 0..64 bytes")
        try check((1...64).contains(Data(e.accountName.utf8).count), "account_name 1..64 bytes")
        try check((1...64).contains(seed.count), "decoded seed must be 1..64 bytes")
    }
}
