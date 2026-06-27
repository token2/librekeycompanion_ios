import XCTest
@testable import LibreKeyCompanion

/// Mirrors the Android app's principle: security-sensitive logic is verified
/// against published spec test vectors, not by inspection.
final class OATHCoreTests: XCTestCase {

    /// RFC 4226 Appendix D — HOTP with the canonical ASCII secret.
    func testRFC4226HOTPVectors() {
        let secret = Data("12345678901234567890".utf8)
        let expected = ["755224","287082","359152","969429","338314",
                        "254676","287922","162583","399871","520489"]
        for c in 0..<10 {
            XCTAssertEqual(OATHCore.hotp(secret: secret, counter: UInt64(c),
                                         digits: 6, algorithm: .sha1),
                           expected[c], "HOTP mismatch at counter \(c)")
        }
    }

    /// RFC 6238 — TOTP with SHA1/SHA256/SHA512 seeds, 8 digits.
    func testRFC6238TOTPVectors() {
        let s1   = Data("12345678901234567890".utf8)
        let s256 = Data("12345678901234567890123456789012".utf8)
        let s512 = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)
        let cases: [(TimeInterval, Data, OATHAlgorithm, String)] = [
            (59,          s1,   .sha1,   "94287082"),
            (1111111109,  s1,   .sha1,   "07081804"),
            (1111111111,  s1,   .sha1,   "14050471"),
            (1234567890,  s1,   .sha1,   "89005924"),
            (2000000000,  s1,   .sha1,   "69279037"),
            (20000000000, s1,   .sha1,   "65353130"),
            (59,          s256, .sha256, "46119246"),
            (59,          s512, .sha512, "90693936"),
            (1234567890,  s256, .sha256, "91819424"),
            (1234567890,  s512, .sha512, "93441116"),
        ]
        for (t, secret, algo, exp) in cases {
            XCTAssertEqual(OATHCore.totp(secret: secret, time: t, digits: 8, algorithm: algo),
                           exp, "TOTP mismatch at t=\(t) algo=\(algo.rawValue)")
        }
    }

    func testBase32Decode() {
        // "Hello!" + 0xDEADBEEF
        XCTAssertEqual(Base32.decode("JBSWY3DPEHPK3PXP"),
                       Data([0x48,0x65,0x6C,0x6C,0x6F,0x21,0xDE,0xAD,0xBE,0xEF]))
        XCTAssertNil(Base32.decode("0189"))   // invalid Base32 chars
    }

    func testOTPAuthURIParsing() {
        let uri = "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=8&period=60"
        let parsed = OTPAuthURI(uri)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.kind, .totp)
        XCTAssertEqual(parsed?.label, "ACME:alice")
        XCTAssertEqual(parsed?.algorithm, .sha256)
        XCTAssertEqual(parsed?.digits, 8)
        XCTAssertEqual(parsed?.period, 60)
    }

    func testTLVRoundTrip() {
        let encoded = TLV.encode(tag: 0x71, value: Data("abc".utf8))
                    + TLV.encode(tag: 0x73, value: Data([0x01, 0x02]))
        let parsed = TLV.parse(encoded)
        XCTAssertEqual(parsed.count, 2)
        XCTAssertEqual(parsed[0].tag, 0x71)
        XCTAssertEqual(parsed[0].value, Data("abc".utf8))
        XCTAssertEqual(parsed[1].value, Data([0x01, 0x02]))
    }

    func testAPDUExtendedLengthEncoding() {
        let big = Data(repeating: 0xAB, count: 300)
        let apdu = APDU(cla: 0x00, ins: 0x01, p1: 0x00, p2: 0x00, data: big, le: 0)
        let bytes = apdu.encoded()
        // 4 header + 3 extended Lc + 300 data
        XCTAssertEqual(bytes.count, 4 + 3 + 300)
        XCTAssertEqual(bytes[4], 0x00)            // extended-length marker
    }
}
