import XCTest
import CommonCrypto
@testable import LibreKeyCompanion

/// Golden-vector tests for the OTP-PIN session crypto. These vectors were
/// computed independently (Python) and are the same ones that validate the
/// Android `Token2PinCrypto.kt`. If any of these fail, the on-wire bytes will not
/// match the device and every VERIFY will return 6982 — so keep them green.
final class Token2PinCryptoTests: XCTestCase {

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private func bytes(_ b: [UInt8]) -> Data { Data(b) }
    private func rep(_ v: UInt8, _ n: Int) -> Data { Data(repeating: v, count: n) }

    /// Session-key ladder from shared = 0x11 * 32.
    func testSessionKeyDerivation() {
        let keys = Token2PinCrypto.deriveSessionKeys(sharedX: rep(0x11, 32))
        XCTAssertEqual(hex(keys.enc),
            "165cab17060f224276bfc144f66aa65fb25c574ffd1864bec8a0c323f39000e7")
        XCTAssertEqual(hex(keys.mac),
            "ff7131f085cd3f668b506029c679e78bacb967df9b3eccd16794ff842b8a6d1d")
    }

    /// Auth tag = HMAC(mac = 0x07*32, data = 0x00..0x0f)[:16].
    func testAuthTag16() {
        let data = Data((0..<16).map { UInt8($0) })
        let tag = Token2PinCrypto.sessionAuthTag(macKey: rep(0x07, 32), data: data)
        XCTAssertEqual(hex(tag), "1b3b127eafc0f864b62154c338a7d526")
    }

    /// VERIFY nested layer: pin="1357924", rand=0x42*16, enc=0x09*32.
    /// Decrypt the outer to recover the inner block and check it.
    func testVerifyBuildNestedInner() throws {
        let keys = Token2PinCrypto.SessionKeys(enc: rep(0x09, 32), mac: rep(0x07, 32))
        let rand = rep(0x42, 16)
        let out = try Token2PinCrypto.buildVerifyPinData(keys, pin: Data("1357924".utf8), rand: rand)
        XCTAssertEqual(out.count, 32)
        let iv = out.prefix(16)
        let outer = out.suffix(16)
        let inner = try aesCBCNoPadDecrypt(key: keys.enc, iv: Data(iv), data: Data(outer))
        XCTAssertEqual(hex(inner), "323753e192ef74d8c51a48d3109e1092")
    }

    /// SET NewPin block: pin="1357924" → 0x07 0x64 0x07 || "1357924".
    func testSetPinNewPinBlockAndTag() throws {
        let keys = Token2PinCrypto.SessionKeys(enc: rep(0x09, 32), mac: rep(0x07, 32))
        let sp = try Token2PinCrypto.buildSetPinData(keys, pin: Data("1357924".utf8))
        let iv = sp.prefix(16)
        let enc = sp.dropFirst(16).dropLast(16)
        let auth = sp.suffix(16)
        let dec = try aesCBCPKCS7Decrypt(key: keys.enc, iv: Data(iv), data: Data(enc))
        XCTAssertEqual(hex(dec), "07640731333537393234")
        let expectTag = Token2PinCrypto.sessionAuthTag(macKey: keys.mac, data: Data(enc))
        XCTAssertEqual(hex(Data(auth)), hex(expectTag))
    }

    // MARK: - local AES-CBC decrypt helpers (test-only)

    private func aesCBCNoPadDecrypt(key: Data, iv: Data, data: Data) throws -> Data {
        try aes(kCCDecrypt, key: key, iv: iv, data: data, pkcs7: false)
    }
    private func aesCBCPKCS7Decrypt(key: Data, iv: Data, data: Data) throws -> Data {
        try aes(kCCDecrypt, key: key, iv: iv, data: data, pkcs7: true)
    }
    private func aes(_ op: Int, key: Data, iv: Data, data: Data, pkcs7: Bool) throws -> Data {
        var outLen = 0
        var out = Data(count: data.count + kCCBlockSizeAES128)
        let opt: CCOptions = pkcs7 ? CCOptions(kCCOptionPKCS7Padding) : 0
        let status = out.withUnsafeMutableBytes { o in
            data.withUnsafeBytes { i in key.withUnsafeBytes { k in iv.withUnsafeBytes { v in
                CCCrypt(CCOperation(op), CCAlgorithm(kCCAlgorithmAES), opt,
                        k.baseAddress, key.count, v.baseAddress,
                        i.baseAddress, data.count, o.baseAddress, o.count, &outLen)
            }}}
        }
        XCTAssertEqual(status, Int32(kCCSuccess))
        out.removeSubrange(outLen..<out.count)
        return out
    }
}
