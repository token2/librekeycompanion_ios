import Foundation
import CryptoKit
import CommonCrypto

/// CTAP2 PIN/UV auth protocol crypto — both v1 and v2.
///
/// Ported from the Android `fido/ctap/PinUvAuthProtocol.kt`, which is verified
/// against the published CTAP2.1 test vectors (the v1 SHA-256 KDF, the v2 HKDF
/// dual-key derivation with info strings "CTAP2 AES key" / "CTAP2 HMAC key", and
/// the HMACs). iOS uses CryptoKit for ECDH/HKDF/HMAC and CommonCrypto for the
/// (unpadded) AES-CBC the protocol requires.
///
///  v1: sharedSecret = SHA-256(Z.x); AES-256-CBC zero IV; auth = HMAC-SHA-256 left 16.
///  v2: HKDF-SHA-256(salt=32 zero) -> aesKey + hmacKey; AES-256-CBC random IV
///      prepended; auth = full 32-byte HMAC-SHA-256.
protocol PinUvAuthProtocol: AnyObject {
    var version: Int { get }
    /// COSE_Key (kty/alg/crv/x/y) of the platform public key for keyAgreement.
    func platformCoseKey() -> [Cbor.MapKey: Cbor.Value]
    /// Derive the per-session shared secret from the authenticator's key (raw X,Y).
    func encapsulate(authX: Data, authY: Data) throws -> SharedSecret
}

/// Derived per-session keys + the operations that use them.
final class SharedSecret {
    private let aesKey: Data
    private let hmacKey: Data
    private let proto: PinUvAuthProtocolBase

    init(aesKey: Data, hmacKey: Data, proto: PinUvAuthProtocolBase) {
        self.aesKey = aesKey; self.hmacKey = hmacKey; self.proto = proto
    }
    func encrypt(_ plaintext: Data) throws -> Data { try proto.encrypt(key: aesKey, data: plaintext) }
    func decrypt(_ ciphertext: Data) throws -> Data { try proto.decrypt(key: aesKey, data: ciphertext) }
    func authenticate(_ message: Data) -> Data { proto.authenticate(key: hmacKey, msg: message) }
}

/// Shared base providing the ephemeral keypair, ECDH, and COSE encoding.
class PinUvAuthProtocolBase: PinUvAuthProtocol {
    let version: Int
    fileprivate let priv: P256.KeyAgreement.PrivateKey

    init(version: Int) {
        self.version = version
        self.priv = P256.KeyAgreement.PrivateKey()
    }

    /// Raw 32-byte shared X coordinate from ECDH with the authenticator key.
    func sharedX(authX: Data, authY: Data) throws -> Data {
        var uncompressed = Data([0x04]); uncompressed.append(authX); uncompressed.append(authY)
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: uncompressed)
        let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
        return shared.withUnsafeBytes { Data($0) }     // 32-byte X
    }

    func platformCoseKey() -> [Cbor.MapKey: Cbor.Value] {
        let x963 = priv.publicKey.x963Representation    // 0x04 || X || Y
        let x = x963.subdata(in: 1..<33)
        let y = x963.subdata(in: 33..<65)
        // COSE_Key: kty=EC2(2), alg=ECDH-ES+HKDF-256(-25), crv=P256(1), x, y
        return [
            .int(1): .uint(2),
            .int(3): .nint(-25),
            .int(-1): .uint(1),
            .int(-2): .bytes(x),
            .int(-3): .bytes(y),
        ]
    }

    func encapsulate(authX: Data, authY: Data) throws -> SharedSecret { fatalError("override") }

    // Subclasses override the primitives.
    func encrypt(key: Data, data: Data) throws -> Data { fatalError("override") }
    func decrypt(key: Data, data: Data) throws -> Data { fatalError("override") }
    func authenticate(key: Data, msg: Data) -> Data { fatalError("override") }

    // AES-256-CBC, NO padding (CTAP pads PINs itself to block multiples).
    static func aesCBC(_ op: Int, key: Data, iv: Data, data: Data) throws -> Data {
        var outLen = 0
        let keyCount = key.count
        let dataCount = data.count
        var out = Data(count: data.count + kCCBlockSizeAES128)
        let status = out.withUnsafeMutableBytes { ob in
            data.withUnsafeBytes { ib in
                key.withUnsafeBytes { kb in
                    iv.withUnsafeBytes { vb in
                        CCCrypt(CCOperation(op), CCAlgorithm(kCCAlgorithmAES),
                                0,   // no padding
                                kb.baseAddress, keyCount, vb.baseAddress,
                                ib.baseAddress, dataCount,
                                ob.baseAddress, ob.count, &outLen)
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw KeyError.transportFailed("AES-CBC failed (\(status))") }
        out.removeSubrange(outLen..<out.count)
        return out
    }

    /// HKDF-SHA-256 via CryptoKit.
    static func hkdf(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt.isEmpty ? Data(count: 32) : salt,
            info: info,
            outputByteCount: length)
        return key.withUnsafeBytes { Data($0) }
    }

    static func hmacSha256(key: Data, msg: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
    }
}

/// PIN/UV protocol v1.
final class PinUvAuthV1: PinUvAuthProtocolBase {
    init() { super.init(version: 1) }

    override func encapsulate(authX: Data, authY: Data) throws -> SharedSecret {
        let z = try sharedX(authX: authX, authY: authY)
        let s = Data(SHA256.hash(data: z))             // 32-byte session key
        return SharedSecret(aesKey: s, hmacKey: s, proto: self)
    }
    override func encrypt(key: Data, data: Data) throws -> Data {
        try Self.aesCBC(kCCEncrypt, key: key, iv: Data(count: 16), data: data)
    }
    override func decrypt(key: Data, data: Data) throws -> Data {
        try Self.aesCBC(kCCDecrypt, key: key, iv: Data(count: 16), data: data)
    }
    override func authenticate(key: Data, msg: Data) -> Data {
        Self.hmacSha256(key: key, msg: msg).prefix(16)   // left 16 bytes
    }
}

/// PIN/UV protocol v2.
final class PinUvAuthV2: PinUvAuthProtocolBase {
    init() { super.init(version: 2) }

    override func encapsulate(authX: Data, authY: Data) throws -> SharedSecret {
        let z = try sharedX(authX: authX, authY: authY)
        let aes = Self.hkdf(ikm: z, salt: Data(count: 32), info: Data("CTAP2 AES key".utf8), length: 32)
        let mac = Self.hkdf(ikm: z, salt: Data(count: 32), info: Data("CTAP2 HMAC key".utf8), length: 32)
        return SharedSecret(aesKey: aes, hmacKey: mac, proto: self)
    }
    override func encrypt(key: Data, data: Data) throws -> Data {
        var iv = Data(count: 16)
        _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        let ct = try Self.aesCBC(kCCEncrypt, key: key, iv: iv, data: data)
        return iv + ct                                  // IV prepended
    }
    override func decrypt(key: Data, data: Data) throws -> Data {
        let iv = data.prefix(16)
        return try Self.aesCBC(kCCDecrypt, key: key, iv: iv, data: data.dropFirst(16))
    }
    override func authenticate(key: Data, msg: Data) -> Data {
        Self.hmacSha256(key: key, msg: msg)             // full 32 bytes
    }
}
