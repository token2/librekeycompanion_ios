import XCTest
@testable import LibreKeyCompanion

/// Captures the last transmitted APDU so PUT/DELETE framing can be asserted
/// against the YKOATH spec without real hardware.
final class MockTransport: KeyTransport {
    var isConnected: Bool = true
    var sent: [APDU] = []
    var nextResponse = APDUResponse(data: Data(), sw1: 0x90, sw2: 0x00)

    func transmit(_ apdu: APDU) async throws -> APDUResponse {
        sent.append(apdu)
        return nextResponse
    }
}

final class YKOATHFramingTests: XCTestCase {

    /// PUT of a TOTP credential with requireTouch must include the bare
    /// property byte (0x78 0x02) and no IMF tag.
    func testPutTOTPWithTouch() async throws {
        let mock = MockTransport()
        let applet = YKOATHApplet(transport: mock)
        let uri = OTPAuthURI("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME")!
        try await applet.put(uri, requireTouch: true)

        let put = mock.sent.last!
        XCTAssertEqual(put.ins, 0x01)
        let d = put.data
        // name tag 0x71 present
        XCTAssertTrue(d.contains(0x71))
        // key tag 0x73 present
        XCTAssertTrue(d.contains(0x73))
        // property byte sequence 0x78 0x02 present, contiguously
        XCTAssertTrue(containsSubsequence(d, [0x78, 0x02]))
        // no IMF tag for TOTP
        XCTAssertFalse(d.contains(0x7A))
    }

    /// PUT of an HOTP credential must carry the 4-byte IMF (0x7A len 0x04)
    /// reflecting the URI counter.
    func testPutHOTPCounter() async throws {
        let mock = MockTransport()
        let applet = YKOATHApplet(transport: mock)
        let uri = OTPAuthURI("otpauth://hotp/ACME:bob?secret=JBSWY3DPEHPK3PXP&counter=256")!
        try await applet.put(uri)

        let d = mock.sent.last!.data
        // IMF: tag 0x7A, length 0x04, value 0x00000100 (256 big-endian)
        XCTAssertTrue(containsSubsequence(d, [0x7A, 0x04, 0x00, 0x00, 0x01, 0x00]))
    }

    /// DELETE sends only the name TLV with INS 0x02.
    func testDeleteFraming() async throws {
        let mock = MockTransport()
        let applet = YKOATHApplet(transport: mock)
        let cred = OATHCredential(name: "ACME:alice", kind: .totp, algorithm: .sha1, digits: 6)
        try await applet.delete(cred)

        let del = mock.sent.last!
        XCTAssertEqual(del.ins, 0x02)
        XCTAssertEqual(del.data.first, 0x71)            // name tag
        XCTAssertTrue(del.data.dropFirst(2).elementsEqual(Data("ACME:alice".utf8)))
    }

    private func containsSubsequence(_ data: Data, _ sub: [UInt8]) -> Bool {
        let bytes = [UInt8](data)
        guard sub.count <= bytes.count else { return false }
        for i in 0...(bytes.count - sub.count) where Array(bytes[i..<i+sub.count]) == sub {
            return true
        }
        return false
    }
}
