import Foundation
import CryptoKit
import CommonCrypto

/// OTP-PIN ("privacy protection") session crypto for Token2 PIN+ keys running
/// firmware R3.4 or later.
///
/// This is the authenticated-ECDH-session layer on top of the plain seed-write
/// ECDH in `Token2Crypto`. Ported byte-for-byte from the Android
/// `token2/Token2PinCrypto.kt`, which is itself a port of the Rust reference
/// (`T2TOTP_Authenticator/src/crypto.rs`). If any construction here diverges from
/// the reference, the device answers 6982 and a wrong PIN is indistinguishable
/// from a wrong implementation — so this file is validated against the
/// reference's own test vectors (see `Token2PinCryptoTests`).
///
/// Session-key ladder (all HMAC-SHA256):
///   shared        = ECDH-P256(hostPriv, devPub).X          (32 bytes)
///   pu1PRKey      = HMAC(key = 0x00*32, data = shared)
///   SessionMacKey = HMAC(key = pu1PRKey, data = "TOTP HMAC key" || 0x01)
///   SessionEncKey = HMAC(key = pu1PRKey, data = "TOTP AES key"  || 0x01)
enum Token2PinCrypto {

    /// The two 32-byte session keys from a READ_AGREEMENT_PUBKEY exchange.
    struct SessionKeys {
        let enc: Data
        let mac: Data
    }

    /// A two-step handshake: generate the host keypair, expose its public X||Y to
    /// send in READ_AGREEMENT_PUBKEY, then derive session keys from the device's
    /// returned pubkey using the SAME host private key.
    struct PendingHandshake {
        let hostPubXy: Data
        fileprivate let priv: P256.KeyAgreement.PrivateKey

        func derive(deviceAgreementXy: Data) throws -> SessionKeys {
            guard deviceAgreementXy.count == 64 else {
                throw KeyError.parsing("device agreement pubkey must be 64 bytes")
            }
            var uncompressed = Data([0x04]); uncompressed.append(deviceAgreementXy)
            let devPub = try P256.KeyAgreement.PublicKey(x963Representation: uncompressed)
            let shared = try priv.sharedSecretFromKeyAgreement(with: devPub)
            let sharedX = shared.withUnsafeBytes { Data($0) }   // raw 32-byte X
            return Token2PinCrypto.deriveSessionKeys(sharedX: sharedX)
        }
    }

    // MARK: - Handshake

    /// Generate a host keypair for a two-step handshake.
    static func beginHandshake() -> PendingHandshake {
        let priv = P256.KeyAgreement.PrivateKey()
        let xy = priv.publicKey.x963Representation.dropFirst()   // strip 0x04 → X||Y
        return PendingHandshake(hostPubXy: Data(xy), priv: priv)
    }

    /// The HMAC ladder. `sharedX` is the 32-byte ECDH X coordinate.
    static func deriveSessionKeys(sharedX: Data) -> SessionKeys {
        let zero = Data(repeating: 0, count: 32)
        let pu1 = hmac(key: zero, data: sharedX)
        var macInfo = Data("TOTP HMAC key".utf8); macInfo.append(0x01)
        var encInfo = Data("TOTP AES key".utf8);  encInfo.append(0x01)
        return SessionKeys(enc: hmac(key: pu1, data: encInfo),
                           mac: hmac(key: pu1, data: macInfo))
    }

    // MARK: - Primitives

    private static func hmac(key: Data, data: Data) -> Data {
        let k = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: k)
        return Data(mac)
    }

    private static func sha256(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }

    private static func randomIV() -> Data {
        var iv = Data(count: 16)
        _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        return iv
    }

    /// The 16-byte auth tag form the PIN commands use: HMAC(macKey, data)[0..<16].
    static func sessionAuthTag(macKey: Data, data: Data) -> Data {
        hmac(key: macKey, data: data).prefix(16)
    }

    /// Constant-time check of a received 16-byte session auth tag.
    static func verifyAuthTag(macKey: Data, data: Data, tag: Data) -> Bool {
        guard tag.count == 16 else { return false }
        let expect = sessionAuthTag(macKey: macKey, data: data)
        var diff: UInt8 = 0
        for i in 0..<16 { diff |= expect[expect.startIndex + i] ^ tag[tag.startIndex + i] }
        return diff == 0
    }

    // MARK: - AES-CBC (CommonCrypto; CryptoKit has no CBC)

    private static func aesCBC(_ op: Int, key: Data, iv: Data, data: Data, pkcs7: Bool) throws -> Data {
        guard key.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            throw KeyError.parsing("bad AES key/iv size")
        }
        var outLen = 0
        var out = Data(count: data.count + kCCBlockSizeAES128)
        let options: CCOptions = pkcs7 ? CCOptions(kCCOptionPKCS7Padding) : 0
        let status = out.withUnsafeMutableBytes { outBuf in
            data.withUnsafeBytes { inBuf in
                key.withUnsafeBytes { keyBuf in
                    iv.withUnsafeBytes { ivBuf in
                        CCCrypt(CCOperation(op),
                                CCAlgorithm(kCCAlgorithmAES),
                                options,
                                keyBuf.baseAddress, key.count,
                                ivBuf.baseAddress,
                                inBuf.baseAddress, data.count,
                                outBuf.baseAddress, outBuf.count,
                                &outLen)
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw KeyError.transportFailed("AES-CBC failed (\(status))")
        }
        out.removeSubrange(outLen..<out.count)
        return out
    }

    /// SessionEncKey encrypt (PKCS#7).
    static func sessionEncrypt(key: Data, iv: Data, cleartext: Data) throws -> Data {
        try aesCBC(kCCEncrypt, key: key, iv: iv, data: cleartext, pkcs7: true)
    }
    /// SessionEncKey decrypt WITH PKCS#7 unpadding (for protected enumerate pages).
    static func sessionDecrypt(key: Data, iv: Data, ciphertext: Data) throws -> Data {
        try aesCBC(kCCDecrypt, key: key, iv: iv, data: ciphertext, pkcs7: true)
    }
    /// SessionEncKey decrypt WITHOUT unpadding (raw blocks; for the Rand challenge).
    static func sessionDecryptRaw(key: Data, iv: Data, ciphertext: Data) throws -> Data {
        guard !ciphertext.isEmpty, ciphertext.count % 16 == 0 else { return Data() }
        return try aesCBC(kCCDecrypt, key: key, iv: iv, data: ciphertext, pkcs7: false)
    }
    private static func aesNoPad(_ op: Int, key: Data, iv: Data, data: Data) throws -> Data {
        try aesCBC(op, key: key, iv: iv, data: data, pkcs7: false)
    }

    // MARK: - Command data-field builders

    /// SET_OTP_PIN data: IV || AES-CBC/PKCS7(EncKey, IV, 0x07||retry||len||pin) || HMAC[:16].
    static func buildSetPinData(_ keys: SessionKeys, pin: Data, retry: UInt8 = 0x64) throws -> Data {
        let iv = randomIV()
        var newPin = Data([0x07, retry, UInt8(pin.count)]); newPin.append(pin)
        let enc = try sessionEncrypt(key: keys.enc, iv: iv, cleartext: newPin)
        let auth = sessionAuthTag(macKey: keys.mac, data: enc)
        return iv + enc + auth
    }

    /// VERIFY_OTP_PIN data — nested AES-CBC, no padding:
    ///   inner = AES-nopad(SHA256(pin), SHA256(rand)[:16], rand)
    ///   outer = AES-nopad(EncKey, randomIV, inner);  data = IV || outer
    static func buildVerifyPinData(_ keys: SessionKeys, pin: Data, rand: Data) throws -> Data {
        try buildVerifyPinData(keys, pin: pin, rand: rand, fpEnable: nil)
    }

    /// VERIFY_OTP_PIN with the optional trailing `EncConfig` block (manual §1.14):
    ///   Config    = pkcs7pad16( FpEnable )              // FpEnable = 0x00 / 0x01
    ///   EncConfig = AES-nopad(EncKey, IV, Config)       // SAME IV as the outer block
    ///   data      = IV || outer || EncConfig
    /// When present, the applet sets the fingerprint-protected-OTP flag while
    /// verifying the PIN (§1.20). `fpEnable == nil` omits the block (plain verify).
    static func buildVerifyPinData(_ keys: SessionKeys, pin: Data, rand: Data,
                                   fpEnable: Bool?) throws -> Data {
        guard rand.count == 16 else { throw KeyError.parsing("rand must be 16 bytes") }
        let pinHash = sha256(pin)                      // 32B → AES-256 key
        let iv2 = sha256(rand).prefix(16)
        let inner = try aesNoPad(kCCEncrypt, key: pinHash, iv: Data(iv2), data: rand)
        let iv = randomIV()
        let outer = try aesNoPad(kCCEncrypt, key: keys.enc, iv: iv, data: inner)
        guard let fp = fpEnable else { return iv + outer }
        let config = pkcs7Pad16(Data([fp ? 0x01 : 0x00]))
        let encConfig = try aesNoPad(kCCEncrypt, key: keys.enc, iv: iv, data: config)
        return iv + outer + encConfig
    }

    /// CHANGE_OTP_PIN / remove (empty newPin) data:
    ///   NewPinEnc     = AES-nopad(EncKey, IV, pkcs7pad16(0x07||0x64||len||newPin))
    ///   OldPinHashEnc = AES-nopad(EncKey, IV, SHA256(current)[:16])   // SAME IV
    ///   data = IV || NewPinEnc || HMAC(NewPinEnc)[:16] || OldPinHashEnc
    static func buildChangePinData(_ keys: SessionKeys, newPin: Data, currentPin: Data) throws -> Data {
        var bodyPlain = Data([0x07, 0x64, UInt8(newPin.count)]); bodyPlain.append(newPin)
        let body = pkcs7Pad16(bodyPlain)
        let iv = randomIV()
        let newPinEnc = try aesNoPad(kCCEncrypt, key: keys.enc, iv: iv, data: body)
        let oldPinHash = sha256(currentPin).prefix(16)
        let oldPinHashEnc = try aesNoPad(kCCEncrypt, key: keys.enc, iv: iv, data: Data(oldPinHash))
        let auth = sessionAuthTag(macKey: keys.mac, data: newPinEnc + oldPinHashEnc)
        return iv + newPinEnc + auth + oldPinHashEnc
    }

    /// PIN-protected WRITE_SEED data (used while a verify window is open):
    ///   data = IV || AES-CBC/PKCS7(EncKey, IV, cleartext) || HMAC[:16].
    static func buildProtectedWriteData(_ keys: SessionKeys, cleartext: Data) throws -> Data {
        let iv = randomIV()
        let enc = try sessionEncrypt(key: keys.enc, iv: iv, cleartext: cleartext)
        let auth = sessionAuthTag(macKey: keys.mac, data: enc)
        return iv + enc + auth
    }

    private static func pkcs7Pad16(_ d: Data) -> Data {
        let pad = 16 - (d.count % 16)
        return d + Data(repeating: UInt8(pad), count: pad)
    }
}
