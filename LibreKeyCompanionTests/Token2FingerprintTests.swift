import XCTest
import CommonCrypto
@testable import LibreKeyCompanion

/// Pins the §1.14 EncConfig block and the §1.20 fingerprint capture-poll loop
/// to the same behaviour as the Android port (Token2PinCryptoFingerprintTest /
/// Token2FingerprintPollTest), which is validated against the keyroost
/// hardware-tested reference.
final class Token2FingerprintTests: XCTestCase {

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private func rep(_ v: UInt8, _ n: Int) -> Data { Data(repeating: v, count: n) }

    private let keys = Token2PinCrypto.SessionKeys(enc: Data((0..<32).map(UInt8.init)),
                                                   mac: Data(repeating: 0x07, count: 32))
    private let pin = Data("123456".utf8)
    private let rand = Data((0..<16).map { UInt8(0xA0 + $0) })

    // MARK: EncConfig layout (§1.14)

    func testLegacyVerifyIs32Bytes() throws {
        XCTAssertEqual(try Token2PinCrypto.buildVerifyPinData(keys, pin: pin, rand: rand).count, 32)
        XCTAssertEqual(try Token2PinCrypto.buildVerifyPinData(keys, pin: pin, rand: rand, fpEnable: nil).count, 32)
    }

    func testEncConfigSameIVEnable() throws {
        let data = try Token2PinCrypto.buildVerifyPinData(keys, pin: pin, rand: rand, fpEnable: true)
        XCTAssertEqual(data.count, 48)
        let iv = Data(data.prefix(16))
        let encConfig = Data(data.suffix(16))
        // Config = PKCS#7-pad16(0x01) = 01 0f*15
        let config = Data([0x01] + Array(repeating: UInt8(0x0F), count: 15))
        XCTAssertEqual(hex(encConfig), hex(try aesNoPadEncrypt(key: keys.enc, iv: iv, data: config)))
    }

    func testEncConfigSameIVDisable() throws {
        let data = try Token2PinCrypto.buildVerifyPinData(keys, pin: pin, rand: rand, fpEnable: false)
        XCTAssertEqual(data.count, 48)
        let iv = Data(data.prefix(16))
        let encConfig = Data(data.suffix(16))
        let config = Data([0x00] + Array(repeating: UInt8(0x0F), count: 15))
        XCTAssertEqual(hex(encConfig), hex(try aesNoPadEncrypt(key: keys.enc, iv: iv, data: config)))
    }

    // MARK: capture-poll state machine (§1.20)

    private func makeApplet() -> Token2OTPApplet { Token2OTPApplet(transport: DummyTransport()) }

    func testStart9100PollsUntil9000() async throws {
        let applet = makeApplet()
        var queue: [UInt16] = [0x9100, 0x9100, 0x9000]
        var pollCount = 0
        let sw = try await applet.pollFingerprintCapture(
            start: { 0x9100 },
            poll: { pollCount += 1; return queue.removeFirst() })
        XCTAssertEqual(sw, 0x9000)
        XCTAssertEqual(pollCount, 3)
    }

    func testStart9000NoPoll() async throws {
        let applet = makeApplet()
        var pollCount = 0
        let sw = try await applet.pollFingerprintCapture(
            start: { 0x9000 },
            poll: { pollCount += 1; return 0x9000 })
        XCTAssertEqual(sw, 0x9000)
        XCTAssertEqual(pollCount, 0)
    }

    func testNeverTouchedTimesOutAs6FFA() async throws {
        let applet = makeApplet()
        let sw = try await applet.pollFingerprintCapture(start: { 0x9100 }, poll: { 0x9100 })
        XCTAssertEqual(sw, 0x6FFA)
    }

    func testTerminalErrorPassedThrough() async throws {
        let applet = makeApplet()
        let sw = try await applet.pollFingerprintCapture(start: { 0x9100 }, poll: { 0x6982 })
        XCTAssertEqual(sw, 0x6982)
    }

    // MARK: helpers

    private func aesNoPadEncrypt(key: Data, iv: Data, data: Data) throws -> Data {
        var outLen = 0
        var out = Data(count: data.count + kCCBlockSizeAES128)
        let status = out.withUnsafeMutableBytes { o in
            data.withUnsafeBytes { i in key.withUnsafeBytes { k in iv.withUnsafeBytes { v in
                CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), 0,
                        k.baseAddress, key.count, v.baseAddress,
                        i.baseAddress, data.count, o.baseAddress, o.count, &outLen)
            }}}
        }
        XCTAssertEqual(status, Int32(kCCSuccess))
        out.removeSubrange(outLen..<out.count)
        return out
    }
}

/// Minimal transport that never transmits — the poll-loop tests inject their own
/// start/poll closures, so transmit is unused.
private final class DummyTransport: KeyTransport {
    var isConnected: Bool { true }
    func transmit(_ apdu: APDU) async throws -> APDUResponse {
        throw KeyError.notConnected
    }
}
