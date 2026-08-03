import XCTest
@testable import LibreKeyCompanion

/// A transport that answers SELECT with a scripted password-protected SELECT
/// response and computes a correct (or deliberately wrong) VALIDATE proof, so
/// the unlock handshake can be exercised without a physical key.
final class ScriptedOATHTransport: KeyTransport {
    var isConnected: Bool = true
    var sent: [APDU] = []

    let deviceId: Data
    let cardChallenge: Data
    /// The key the "card" authenticates with. Set it to something else to
    /// simulate a wrong password.
    var cardAccessKey: Data
    /// When set, VALIDATE answers with this status instead of 0x9000.
    var validateStatus: UInt16?
    /// When true, VALIDATE returns a proof computed with the wrong key.
    var forgeProof = false
    /// Status returned by LIST — 0x6982 until VALIDATE succeeds.
    private var unlocked = false

    init(deviceId: Data, cardChallenge: Data, cardAccessKey: Data) {
        self.deviceId = deviceId
        self.cardChallenge = cardChallenge
        self.cardAccessKey = cardAccessKey
    }

    func transmit(_ apdu: APDU) async throws -> APDUResponse {
        sent.append(apdu)
        switch apdu.ins {
        case 0xA4:   // SELECT
            var body = TLV.encode(tag: 0x79, value: Data([5, 4, 3]))
            body.append(TLV.encode(tag: 0x71, value: deviceId))
            body.append(TLV.encode(tag: 0x74, value: cardChallenge))
            return APDUResponse(data: body, sw1: 0x90, sw2: 0x00)

        case 0xA3:   // VALIDATE
            if let sw = validateStatus {
                return APDUResponse(data: Data(), sw1: UInt8(sw >> 8), sw2: UInt8(sw & 0xFF))
            }
            let tlvs = TLV.parse(apdu.data)
            guard let hostChallenge = tlvs.first(where: { $0.tag == 0x74 })?.value else {
                return APDUResponse(data: Data(), sw1: 0x6A, sw2: 0x80)
            }
            let key = forgeProof ? Data(repeating: 0xFF, count: 16) : cardAccessKey
            let proof = OATHPassword.hmac(algorithmCode: 0x01, key: key, data: hostChallenge)
            unlocked = true
            return APDUResponse(data: TLV.encode(tag: 0x75, value: proof), sw1: 0x90, sw2: 0x00)

        case 0xA1:   // LIST
            guard unlocked else { return APDUResponse(data: Data(), sw1: 0x69, sw2: 0x82) }
            return APDUResponse(data: Data(), sw1: 0x90, sw2: 0x00)

        default:
            return APDUResponse(data: Data(), sw1: 0x90, sw2: 0x00)
        }
    }
}

final class OATHPasswordTests: XCTestCase {

    private func hex(_ s: String) -> Data { OATHPassword.data(fromHex: s.uppercased()) }

    private let deviceId = Data([1, 2, 3, 4, 5, 6, 7, 8])
    private let password = "OpenSesame"
    /// PBKDF2-HMAC-SHA1("OpenSesame", 01..08, 1000, 16), computed independently.
    private let expectedAccessKey = "8972ECAB15ACDE10829C3983C6C81864"

    // MARK: - Derivation

    func testRFC6070PBKDF2Vectors() {
        XCTAssertEqual(
            OATHPassword.pbkdf2HmacSHA1(password: Data("password".utf8), salt: Data("salt".utf8),
                                        iterations: 1, length: 20),
            hex("0c60c80f961f0e71f3a9b524af6012062fe037a6"))
        XCTAssertEqual(
            OATHPassword.pbkdf2HmacSHA1(password: Data("password".utf8), salt: Data("salt".utf8),
                                        iterations: 2, length: 20),
            hex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"))
        // The iteration count the OATH applet uses.
        XCTAssertEqual(
            OATHPassword.pbkdf2HmacSHA1(password: Data("password".utf8), salt: Data("salt".utf8),
                                        iterations: 4096, length: 20),
            hex("4b007901b765489abead49d926f721d065a429c1"))
        // Multi-block output exercises the block counter, unlike the 16-byte case.
        XCTAssertEqual(
            OATHPassword.pbkdf2HmacSHA1(password: Data("passwordPASSWORDpassword".utf8),
                                        salt: Data("saltSALTsaltSALTsaltSALTsaltSALTsalt".utf8),
                                        iterations: 4096, length: 25),
            hex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"))
    }

    func testAccessKeyDerivation() throws {
        let key = try OATHPassword.deriveAccessKey(password: password, deviceId: deviceId)
        XCTAssertEqual(key.count, OATHPassword.keyLength)
        XCTAssertEqual(OATHPassword.hex(key), expectedAccessKey)
    }

    /// The password is hashed as UTF-8, not as Latin-1 — the two differ for any
    /// non-ASCII password, and the applet gives no diagnostic beyond 6982.
    func testNonASCIIPasswordUsesUTF8() throws {
        let derived = try OATHPassword.deriveAccessKey(password: "pässwörd", deviceId: deviceId)
        XCTAssertEqual(derived,
                       OATHPassword.pbkdf2HmacSHA1(password: Data("pässwörd".utf8),
                                                   salt: deviceId, iterations: 1000, length: 16))
        let latin1 = "pässwörd".data(using: .isoLatin1)!
        XCTAssertNotEqual(derived,
                          OATHPassword.pbkdf2HmacSHA1(password: latin1, salt: deviceId,
                                                      iterations: 1000, length: 16))
    }

    func testEmptyPasswordRejected() {
        XCTAssertThrowsError(try OATHPassword.deriveAccessKey(password: "", deviceId: deviceId))
    }

    func testRFC2202HMACVector() {
        XCTAssertEqual(
            OATHPassword.hmac(algorithmCode: 0x01,
                              key: hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                              data: Data("Hi There".utf8)),
            hex("b617318655057264e28bc0b6fb378c8ef146be00"))
    }

    func testConstantTimeEquals() {
        let a = hex("00112233445566778899aabbccddeeff")
        XCTAssertTrue(OATHPassword.constantTimeEquals(a, a))
        XCTAssertFalse(OATHPassword.constantTimeEquals(a, a.prefix(15)))
        var b = a; b[15] ^= 0x01
        XCTAssertFalse(OATHPassword.constantTimeEquals(a, b))
    }

    func testHexRoundTrip() {
        let bytes = hex("0a1b2c3d4e5f")
        XCTAssertEqual(OATHPassword.hex(bytes), "0A1B2C3D4E5F")
        XCTAssertEqual(OATHPassword.data(fromHex: OATHPassword.hex(bytes)), bytes)
    }

    // MARK: - VALIDATE handshake

    func testSelectReportsPasswordProtection() async throws {
        let card = ScriptedOATHTransport(deviceId: deviceId,
                                         cardChallenge: Data(repeating: 0xA5, count: 8),
                                         cardAccessKey: hex(expectedAccessKey))
        let applet = YKOATHApplet(transport: card)
        let info = try await applet.select()
        XCTAssertTrue(info.isPasswordProtected)
        XCTAssertEqual(info.deviceId, deviceId)
        XCTAssertEqual(info.algorithmCode, 0x01)   // absent 0x7B tag defaults to SHA-1
        XCTAssertTrue(applet.isLocked)
    }

    /// The unlock must send HMAC(accessKey, cardChallenge) under tag 0x75 plus an
    /// 8-byte host challenge under 0x74, and LIST must then succeed.
    func testValidateFramingAndUnlock() async throws {
        let cardChallenge = Data(repeating: 0xA5, count: 8)
        let accessKey = hex(expectedAccessKey)
        let card = ScriptedOATHTransport(deviceId: deviceId, cardChallenge: cardChallenge,
                                         cardAccessKey: accessKey)
        let applet = YKOATHApplet(transport: card)
        _ = try await applet.select()
        try await applet.validate(accessKey: accessKey)
        XCTAssertFalse(applet.isLocked)

        let validate = card.sent.first { $0.ins == 0xA3 }
        let tlvs = TLV.parse(validate!.data)
        XCTAssertEqual(tlvs.first(where: { $0.tag == 0x75 })?.value,
                       OATHPassword.hmac(algorithmCode: 0x01, key: accessKey, data: cardChallenge))
        XCTAssertEqual(tlvs.first(where: { $0.tag == 0x74 })?.value.count, 8)

        _ = try await applet.list()   // would throw .oathPasswordRequired if still locked
    }

    func testWrongPasswordSurfacesTypedError() async throws {
        let card = ScriptedOATHTransport(deviceId: deviceId,
                                         cardChallenge: Data(repeating: 0xA5, count: 8),
                                         cardAccessKey: hex(expectedAccessKey))
        card.validateStatus = 0x6982
        let applet = YKOATHApplet(transport: card)
        _ = try await applet.select()
        do {
            try await applet.validate(accessKey: Data(repeating: 0x00, count: 16))
            XCTFail("expected a rejection")
        } catch KeyError.oathPasswordIncorrect(let id) {
            XCTAssertEqual(id, deviceId)
        }
    }

    /// A card that accepts our proof but cannot answer our challenge is not the
    /// key we think it is — the unlock must fail rather than proceed.
    func testMutualAuthenticationRejectsBadProof() async throws {
        let card = ScriptedOATHTransport(deviceId: deviceId,
                                         cardChallenge: Data(repeating: 0xA5, count: 8),
                                         cardAccessKey: hex(expectedAccessKey))
        card.forgeProof = true
        let applet = YKOATHApplet(transport: card)
        _ = try await applet.select()
        do {
            try await applet.validate(accessKey: hex(expectedAccessKey))
            XCTFail("expected mutual authentication to fail")
        } catch KeyError.parsing {
            // expected
        }
    }

    /// A locked applet answers every instruction with 6982; that must arrive as
    /// a password request, not a bare status word.
    func testLockedListRaisesPasswordRequired() async throws {
        let card = ScriptedOATHTransport(deviceId: deviceId,
                                         cardChallenge: Data(repeating: 0xA5, count: 8),
                                         cardAccessKey: hex(expectedAccessKey))
        let applet = YKOATHApplet(transport: card)
        _ = try await applet.select()
        do {
            _ = try await applet.list()
            XCTFail("expected the locked applet to refuse LIST")
        } catch KeyError.oathPasswordRequired(let id) {
            XCTAssertEqual(id, deviceId)
        }
    }
}
