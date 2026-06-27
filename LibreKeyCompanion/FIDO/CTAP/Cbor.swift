import Foundation

/// Minimal CBOR codec for CTAP2. Supports the subset CTAP uses: unsigned/negative
/// ints, byte strings, text strings, arrays, and maps (int or text keys).
/// Encoding follows CTAP2 canonical CBOR: map keys sorted, definite lengths,
/// shortest-form integers.
///
/// Ported from the Android `fido/ctap/Cbor.kt`. Deliberately small — just enough
/// to talk to an authenticator correctly. Validated against CTAP test vectors in
/// `CborTests`.
enum Cbor {

    /// A decoded CBOR value. Swift has no `Any?`-friendly numeric story, so values
    /// come back as these cases.
    enum Value: Equatable {
        case uint(UInt64)
        case nint(Int64)            // negative integer
        case bytes(Data)
        case text(String)
        case array([Value])
        case map([MapKey: Value])
        case bool(Bool)
        case null
    }

    /// Map keys in CTAP are either ints or text strings.
    enum MapKey: Hashable {
        case int(Int)
        case text(String)
    }

    struct DecodeError: Error { let message: String }

    // ---- Decoding ----

    static func decode(_ bytes: Data) throws -> Value {
        let (v, _) = try decodeAt([UInt8](bytes), 0)
        return v
    }

    private static func decodeAt(_ b: [UInt8], _ start: Int) throws -> (Value, Int) {
        var i = start
        guard i < b.count else { throw DecodeError(message: "CBOR truncated") }
        let ib = Int(b[i]); i += 1
        let major = ib >> 5
        let info = ib & 0x1F
        let (len, ni) = try readLength(b, i, info)
        i = ni
        switch major {
        case 0:
            return (.uint(len), i)
        case 1:
            return (.nint(-1 - Int64(len)), i)
        case 2:
            let end = i + Int(len)
            guard end <= b.count else { throw DecodeError(message: "byte string overruns") }
            return (.bytes(Data(b[i..<end])), end)
        case 3:
            let end = i + Int(len)
            guard end <= b.count else { throw DecodeError(message: "text overruns") }
            let s = String(bytes: b[i..<end], encoding: .utf8) ?? ""
            return (.text(s), end)
        case 4:
            var out: [Value] = []
            var j = i
            for _ in 0..<Int(len) { let (v, nj) = try decodeAt(b, j); out.append(v); j = nj }
            return (.array(out), j)
        case 5:
            var out: [MapKey: Value] = [:]
            var j = i
            for _ in 0..<Int(len) {
                let (k, jk) = try decodeAt(b, j)
                let (v, jv) = try decodeAt(b, jk)
                out[try normalizeKey(k)] = v
                j = jv
            }
            return (.map(out), j)
        case 7:
            switch info {
            case 20: return (.bool(false), i)
            case 21: return (.bool(true), i)
            case 22: return (.null, i)
            default: return (.null, i)
            }
        default:
            throw DecodeError(message: "Unsupported CBOR major type \(major)")
        }
    }

    private static func normalizeKey(_ k: Value) throws -> MapKey {
        switch k {
        case .uint(let u): return .int(Int(u))
        case .nint(let n): return .int(Int(n))
        case .text(let t): return .text(t)
        default: throw DecodeError(message: "unsupported CBOR map key")
        }
    }

    private static func readLength(_ b: [UInt8], _ i: Int, _ info: Int) throws -> (UInt64, Int) {
        switch info {
        case 0..<24: return (UInt64(info), i)
        case 24:
            guard i < b.count else { throw DecodeError(message: "len byte missing") }
            return (UInt64(b[i]), i + 1)
        case 25: return try readUInt(b, i, 2)
        case 26: return try readUInt(b, i, 4)
        case 27: return try readUInt(b, i, 8)
        default: throw DecodeError(message: "bad CBOR length info \(info)")
        }
    }

    private static func readUInt(_ b: [UInt8], _ i: Int, _ n: Int) throws -> (UInt64, Int) {
        guard i + n <= b.count else { throw DecodeError(message: "uint overruns") }
        var v: UInt64 = 0
        for k in 0..<n { v = (v << 8) | UInt64(b[i + k]) }
        return (v, i + n)
    }

    // ---- Encoding ----

    static func encode(_ value: Value) -> Data {
        var out = Data()
        encodeInto(&out, value)
        return out
    }

    private static func encodeInto(_ out: inout Data, _ value: Value) {
        switch value {
        case .null: out.append(0xF6)
        case .bool(let b): out.append(b ? 0xF5 : 0xF4)
        case .uint(let u): writeHead(&out, 0, u)
        case .nint(let n): writeHead(&out, 1, UInt64(-1 - n))
        case .bytes(let d): writeHead(&out, 2, UInt64(d.count)); out.append(d)
        case .text(let s):
            let u = Data(s.utf8); writeHead(&out, 3, UInt64(u.count)); out.append(u)
        case .array(let a):
            writeHead(&out, 4, UInt64(a.count)); a.forEach { encodeInto(&out, $0) }
        case .map(let m): encodeMap(&out, m)
        }
    }

    private static func encodeMap(_ out: inout Data, _ map: [MapKey: Value]) {
        // CTAP canonical: int keys sorted by value. (All CTAP request maps use int
        // keys.) Text-keyed maps are sorted by encoded-key bytes per RFC 7049 — but
        // CTAP requests never use those, so int-sort suffices here.
        let entries = map.sorted { lhs, rhs in
            switch (lhs.key, rhs.key) {
            case (.int(let a), .int(let b)): return a < b
            case (.text(let a), .text(let b)): return a < b
            case (.int, .text): return true
            case (.text, .int): return false
            }
        }
        writeHead(&out, 5, UInt64(entries.count))
        for e in entries {
            switch e.key {
            case .int(let i): encodeInto(&out, i >= 0 ? .uint(UInt64(i)) : .nint(Int64(i)))
            case .text(let t): encodeInto(&out, .text(t))
            }
            encodeInto(&out, e.value)
        }
    }

    private static func writeHead(_ out: inout Data, _ major: Int, _ len: UInt64) {
        let m = UInt8(major << 5)
        switch len {
        case 0..<24:
            out.append(m | UInt8(len))
        case 24..<0x100:
            out.append(m | 24); out.append(UInt8(len))
        case 0x100..<0x10000:
            out.append(m | 25); out.append(UInt8(len >> 8)); out.append(UInt8(len & 0xFF))
        case 0x10000..<0x1_0000_0000:
            out.append(m | 26)
            for s in [24, 16, 8, 0] { out.append(UInt8((len >> UInt64(s)) & 0xFF)) }
        default:
            out.append(m | 27)
            for s in [56, 48, 40, 32, 24, 16, 8, 0] { out.append(UInt8((len >> UInt64(s)) & 0xFF)) }
        }
    }
}
