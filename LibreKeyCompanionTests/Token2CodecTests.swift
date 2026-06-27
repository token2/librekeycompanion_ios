import XCTest
@testable import LibreKeyCompanion

/// Ported from the Android `Token2CodecTest.kt`. Locks the Swift codec to the
/// same protocol spec vectors (§10.1 parse trace, §10.2 write serialization).
final class Token2CodecTests: XCTestCase {

    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return d
    }

    func testParseSingleTotpEntry() throws {
        // §10.1 with prose-correct leading type byte 0x01 (TOTP), partial flag clear.
        let page = hex("01C1001E0600045465737405616C69636506313233343536")
        let (entries, more) = try Token2Codec.parseEnumPage(page, fullDecode: false)
        XCTAssertFalse(more)
        XCTAssertEqual(entries.count, 1)
        let e = entries[0]
        XCTAssertEqual(e.type, Token2Codec.TYPE_TOTP)
        XCTAssertEqual(e.algorithm, Token2Codec.ALG_SHA1)
        XCTAssertEqual(e.timestep, 30)
        XCTAssertEqual(e.codeLength, 6)
        XCTAssertFalse(e.buttonRequired)
        XCTAssertEqual(e.appName, "Test")
        XCTAssertEqual(e.accountName, "alice")
        XCTAssertEqual(e.otpCode, "123456")
    }

    func testPartialFlagSet() throws {
        let page = hex("81C1001E0600045465737405616C69636506313233343536")
        let (entries, more) = try Token2Codec.parseEnumPage(page, fullDecode: false)
        XCTAssertTrue(more)
        XCTAssertEqual(entries[0].otpCode, "123456")
    }

    func testHotpHasNoCodeTail() throws {
        // type=00 (HOTP) => no otp_code tail.
        let page = hex("00C1001E0600045465737405616C696365")
        let (entries, _) = try Token2Codec.parseEnumPage(page, fullDecode: false)
        XCTAssertEqual(entries[0].type, Token2Codec.TYPE_HOTP)
        XCTAssertNil(entries[0].otpCode)
    }

    func testSerializeWriteMatchesTrace() throws {
        let e = Token2Codec.Entry(type: Token2Codec.TYPE_TOTP, algorithm: Token2Codec.ALG_SHA1,
                                  timestep: 30, codeLength: 6, buttonRequired: false,
                                  appName: "Test", accountName: "alice", seed: Data("Hello".utf8))
        var expected = hex("01C1001E060004")
        expected.append(Data("Test".utf8))
        expected.append(5); expected.append(Data("alice".utf8))
        expected.append(5); expected.append(Data("Hello".utf8))
        XCTAssertEqual(try Token2Codec.serializeWriteEntry(e), expected)
    }

    func testSerializeReadAll() {
        XCTAssertEqual(Token2Codec.serializeReadAll(timestampSeconds: 0),
                       hex("030000000000000000"))
    }

    func testValidateRejectsBadCodeLength() {
        let e = Token2Codec.Entry(type: Token2Codec.TYPE_TOTP, algorithm: Token2Codec.ALG_SHA1,
                                  timestep: 30, codeLength: 12, buttonRequired: false,
                                  appName: "a", accountName: "b", seed: Data("x".utf8))
        XCTAssertThrowsError(try Token2Codec.serializeWriteEntry(e))
    }

    /// The extended-length APDU framing the Token2 applet requires.
    func testExtendedApduFraming() {
        let apdu = APDU(cla: 0x80, ins: 0xC5, p1: 0x01, p2: 0x00, data: Data(), le: 0, forceExtended: true)
        XCTAssertEqual([UInt8](apdu.encoded()), [0x80, 0xC5, 0x01, 0x00, 0x00, 0x00, 0x00])
    }
}
