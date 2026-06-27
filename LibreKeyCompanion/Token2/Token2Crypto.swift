import Foundation
import CryptoKit
import CommonCrypto

/// §7 seed encryption: ephemeral ECDH (NIST P-256) → SHA-256(sharedX) →
/// AES-256-CBC with one of two CONSTANT IVs.
///
/// Ported from the Android `token2/Token2Crypto.kt`. iOS uses CryptoKit for the
/// P-256 ECDH and CommonCrypto for AES-CBC (CryptoKit has no CBC primitive).
/// CryptoKit's `sharedSecretFromKeyAgreement` yields the raw 32-byte X coordinate
/// of the shared point — identical to the Kotlin `generateSecret()` result — so
/// the SHA-256 session-key derivation matches exactly.
///
/// SECURITY: the two IVs are fixed by the device protocol — freshness comes from
/// the per-command ephemeral host keypair, NOT the IV. Do not randomize them.
enum Token2Crypto {

    /// IV-1 — write/delete OTP entries (WRITE_SEED).
    static let IV_WRITE_SEED = Data([0x9D,0xD8,0x91,0x8E,0x34,0xF3,0xCC,0xAB,
                                     0x08,0xCB,0x75,0x18,0xF7,0x19,0x38,0xF1])
    /// IV-2 — button-HOTP seed write/delete (WRITE_HOTP_SEED).
    static let IV_HOTP_SEED = Data(repeating: 0, count: 16)

    /// Build the on-wire ECDH blob: host ephemeral pubkey (64-byte X||Y, no 0x04
    /// prefix) followed by the AES-256-CBC ciphertext of the PKCS#7-padded
    /// cleartext.
    ///
    /// - Parameter devicePubXy: device pubkey as raw X||Y (64 bytes), from GET_ECDH_PUBKEY.
    static func encryptPayload(devicePubXy: Data, cleartext: Data, iv: Data) throws -> Data {
        guard devicePubXy.count == 64 else {
            throw KeyError.parsing("device pubkey must be 64 bytes (X||Y)")
        }

        // Device public key from raw X||Y → an uncompressed point (0x04 || X || Y).
        var uncompressed = Data([0x04])
        uncompressed.append(devicePubXy)
        let devicePub = try P256.KeyAgreement.PublicKey(x963Representation: uncompressed)

        // Host ephemeral keypair.
        let hostPriv = P256.KeyAgreement.PrivateKey()
        let hostPub = hostPriv.publicKey

        // ECDH shared secret = X coordinate (32 bytes).
        let shared = try hostPriv.sharedSecretFromKeyAgreement(with: devicePub)
        let sharedX = shared.withUnsafeBytes { Data($0) }   // 32 bytes, raw X
        let sessionKey = Data(SHA256.hash(data: sharedX))   // AES-256 key

        let ct = try aesCBCEncryptPKCS7(data: cleartext, key: sessionKey, iv: iv)

        return hostPubXy(hostPub) + ct
    }

    /// Host pubkey as raw 64-byte X||Y (strip the leading 0x04 from x963).
    private static func hostPubXy(_ pub: P256.KeyAgreement.PublicKey) -> Data {
        let x963 = pub.x963Representation     // 0x04 || X(32) || Y(32) = 65 bytes
        return x963.dropFirst()               // 64 bytes X||Y
    }

    /// AES-256-CBC with PKCS#7 padding via CommonCrypto.
    private static func aesCBCEncryptPKCS7(data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            throw KeyError.parsing("bad AES key/iv size")
        }
        var outLen = 0
        let keyCount = key.count
        let dataCount = data.count
        var out = Data(count: data.count + kCCBlockSizeAES128)
        let status = out.withUnsafeMutableBytes { outBuf in
            data.withUnsafeBytes { inBuf in
                key.withUnsafeBytes { keyBuf in
                    iv.withUnsafeBytes { ivBuf in
                        CCCrypt(CCOperation(kCCEncrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBuf.baseAddress, keyCount,
                                ivBuf.baseAddress,
                                inBuf.baseAddress, dataCount,
                                outBuf.baseAddress, outBuf.count,
                                &outLen)
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw KeyError.transportFailed("AES-CBC encrypt failed (\(status))")
        }
        out.removeSubrange(outLen..<out.count)
        return out
    }
}
