import Foundation
import CryptoKit

/// RFC 4226 (HOTP) and RFC 6238 (TOTP) computation.
///
/// Ported from the Android app's `oath/` core. Verified against the published
/// RFC test vectors in `OATHCoreTests`.
public enum OATHAlgorithm: String, CaseIterable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"

    /// YKOATH algorithm nibble used in the PUT/CALCULATE type byte.
    public var ykoathCode: UInt8 {
        switch self {
        case .sha1: return 0x01
        case .sha256: return 0x02
        case .sha512: return 0x03
        }
    }
}

public enum OATHKind: String {
    case totp = "TOTP"
    case hotp = "HOTP"

    public var ykoathCode: UInt8 {
        switch self {
        case .hotp: return 0x10
        case .totp: return 0x20
        }
    }
}

public struct OATHCore {

    /// HMAC over an 8-byte big-endian counter, per the chosen hash.
    static func hmac(secret: Data, counter: UInt64, algorithm: OATHAlgorithm) -> Data {
        var be = counter.bigEndian
        let msg = withUnsafeBytes(of: &be) { Data($0) }
        let key = SymmetricKey(data: secret)
        switch algorithm {
        case .sha1:
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: key))
        case .sha256:
            return Data(HMAC<SHA256>.authenticationCode(for: msg, using: key))
        case .sha512:
            return Data(HMAC<SHA512>.authenticationCode(for: msg, using: key))
        }
    }

    /// Dynamic truncation (RFC 4226 §5.3) → zero-padded decimal string.
    public static func hotp(secret: Data, counter: UInt64,
                            digits: Int = 6, algorithm: OATHAlgorithm = .sha1) -> String {
        let mac = hmac(secret: secret, counter: counter, algorithm: algorithm)
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let binary =
            (UInt32(mac[offset] & 0x7F) << 24) |
            (UInt32(mac[offset + 1]) << 16) |
            (UInt32(mac[offset + 2]) << 8) |
            (UInt32(mac[offset + 3]))
        let mod = UInt32(pow(10.0, Double(digits)))
        let code = binary % mod
        return String(format: "%0\(digits)u", code)
    }

    /// TOTP for a given Unix time, default 30-second step (RFC 6238).
    public static func totp(secret: Data, time: TimeInterval = Date().timeIntervalSince1970,
                            step: TimeInterval = 30, t0: TimeInterval = 0,
                            digits: Int = 6, algorithm: OATHAlgorithm = .sha1) -> String {
        let counter = UInt64((time - t0) / step)
        return hotp(secret: secret, counter: counter, digits: digits, algorithm: algorithm)
    }

    /// Seconds remaining in the current TOTP window — drives the countdown ring.
    public static func secondsRemaining(time: TimeInterval = Date().timeIntervalSince1970,
                                        step: TimeInterval = 30) -> Int {
        step <= 0 ? 0 : Int(step - (time.truncatingRemainder(dividingBy: step)))
    }
}
