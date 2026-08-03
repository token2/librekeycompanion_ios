import Foundation
import CryptoKit

/// YKOATH password support: access-key derivation and the HMAC proof used by
/// VALIDATE (INS A3).
///
/// Ported from the Android `oath/OathPassword.kt`. A password-protected OATH
/// applet answers SELECT normally but returns a challenge (tag 0x74) and rejects
/// every other instruction with SW 6982 until VALIDATE succeeds. The access key
/// is
///
///     PBKDF2-HMAC-SHA1(UTF-8(password), salt = device id, 1000 iterations, 16 bytes)
///
/// where the device id is the name TLV (0x71) from the SELECT response.
///
/// PBKDF2 is implemented here on top of CryptoKit rather than called through
/// `CCKeyDerivationPBKDF` so both apps run byte-identical derivations that are
/// pinned by the same RFC 6070 vectors — the key must match whatever desktop
/// tool set the password, and a wrong derivation is indistinguishable from a
/// wrong password on the wire.
public enum OATHPassword {

    public static let iterations = 1000
    public static let keyLength = 16

    public static func deriveAccessKey(password: String, deviceId: Data) throws -> Data {
        let bytes = Data(password.utf8)
        guard !bytes.isEmpty else {
            throw KeyError.parsing("The OATH password must not be empty.")
        }
        return pbkdf2HmacSHA1(password: bytes, salt: deviceId,
                              iterations: iterations, length: keyLength)
    }

    /// RFC 2898 PBKDF2 with HMAC-SHA1 as the PRF (verified against RFC 6070).
    public static func pbkdf2HmacSHA1(password: Data, salt: Data,
                                      iterations: Int, length: Int) -> Data {
        precondition(iterations > 0 && length > 0)
        let key = SymmetricKey(data: password)
        var out = Data()
        var block: UInt32 = 1

        while out.count < length {
            var message = salt
            message.append(contentsOf: [UInt8((block >> 24) & 0xFF),
                                        UInt8((block >> 16) & 0xFF),
                                        UInt8((block >> 8) & 0xFF),
                                        UInt8(block & 0xFF)])
            var u = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
            var t = u
            if iterations > 1 {
                for _ in 2...iterations {
                    u = Data(HMAC<Insecure.SHA1>.authenticationCode(for: u, using: key))
                    for i in 0..<t.count { t[i] ^= u[i] }
                }
            }
            out.append(t)
            block += 1
        }
        return out.prefix(length)
    }

    /// HMAC for a VALIDATE exchange, selected by the applet's algorithm tag
    /// (0x7B). SHA-1 is the default and what every key in the wild reports.
    public static func hmac(algorithmCode: UInt8, key: Data, data: Data) -> Data {
        let k = SymmetricKey(data: key)
        switch algorithmCode {
        case OATHAlgorithm.sha256.ykoathCode:
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: k))
        case OATHAlgorithm.sha512.ykoathCode:
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: k))
        default:
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: k))
        }
    }

    /// Comparison of authentication tags must not leak position via timing.
    public static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }

    public static func hex(_ data: Data) -> String {
        data.map { String(format: "%02X", $0) }.joined()
    }

    public static func data(fromHex hex: String) -> Data {
        var out = Data()
        var index = hex.startIndex
        while let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) {
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return out }
            out.append(byte)
            index = next
        }
        return out
    }
}
