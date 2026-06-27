import Foundation

/// RFC 4648 Base32 (no padding required), used for otpauth:// secrets.
public enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    private static let lookup: [Character: UInt8] = {
        var m: [Character: UInt8] = [:]
        for (i, c) in alphabet.enumerated() { m[c] = UInt8(i) }
        return m
    }()

    public static func decode(_ s: String) -> Data? {
        let cleaned = s.uppercased().replacingOccurrences(of: "=", with: "")
                       .replacingOccurrences(of: " ", with: "")
        var buffer: UInt32 = 0
        var bits = 0
        var out = Data()
        for ch in cleaned {
            guard let v = lookup[ch] else { return nil }
            buffer = (buffer << 5) | UInt32(v)
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> UInt32(bits)) & 0xFF))
            }
        }
        return out
    }
}

/// Parsed representation of an `otpauth://` provisioning URI (Google Authenticator
/// format), as produced by QR scans or manual paste.
public struct OTPAuthURI {
    public let kind: OATHKind
    public let label: String          // "issuer:account" canonical form
    public let secret: Data
    public let algorithm: OATHAlgorithm
    public let digits: Int
    public let period: Int
    public let counter: UInt64

    public init?(_ raw: String) {
        guard let comps = URLComponents(string: raw),
              comps.scheme?.lowercased() == "otpauth",
              let host = comps.host?.lowercased() else { return nil }

        self.kind = host == "hotp" ? .hotp : .totp

        let path = comps.path.hasPrefix("/") ? String(comps.path.dropFirst()) : comps.path
        let items = comps.queryItems ?? []
        func q(_ name: String) -> String? { items.first { $0.name == name }?.value }

        guard let secretStr = q("secret"),
              let secretData = Base32.decode(secretStr) else { return nil }
        self.secret = secretData

        let issuerParam = q("issuer")
        if let issuerParam, !path.contains(":") {
            self.label = "\(issuerParam):\(path)"
        } else {
            self.label = path
        }

        switch q("algorithm")?.uppercased() {
        case "SHA256": self.algorithm = .sha256
        case "SHA512": self.algorithm = .sha512
        default: self.algorithm = .sha1
        }
        self.digits = Int(q("digits") ?? "6") ?? 6
        self.period = Int(q("period") ?? "30") ?? 30
        self.counter = UInt64(q("counter") ?? "0") ?? 0
    }

    /// Token2 stores app and account as separate fields. Split the "issuer:account"
    /// label: the part before the first colon is the app, the rest the account.
    public var issuerForToken2: String {
        if let r = label.range(of: ":") { return String(label[..<r.lowerBound]) }
        return ""
    }
    public var accountForToken2: String {
        if let r = label.range(of: ":") { return String(label[r.upperBound...]) }
        return label
    }
}
