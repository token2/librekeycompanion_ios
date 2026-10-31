import XCTest
@testable import Token2USBFido

/// Wire-level checks against the APDUs captured from an R3.4 key (Oct 2026):
/// SELECT OTP → "1000" 9000; tunnel getInfo → 00 B2 … 9000; FIDO AID → 6A81.
final class Token2USBFidoTests: XCTestCase {
    private final class FakeKey {
        var sent: [Data] = []
        var replies: [(Data, UInt16)]
        init(_ replies: [(Data, UInt16)]) { self.replies = replies }
        func exchange() -> Token2USBFido.Exchange {
            { cla, ins, p1, p2, data in
                self.sent.append(Data([cla, ins, p1, p2]) + data)
                return self.replies.isEmpty ? (data: Data(), sw: 0x6F00) : self.replies.removeFirst()
            }
        }
    }

    private let select = Data([0x00, 0xA4, 0x04, 0x00, 0xF0, 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01])
    private let getInfoReply = Data([0x00, 0xB2, 0x01, 0x83])   // status OK + start of an 18-entry map

    func testSlotNamePrefilter() {
        XCTAssertTrue(Token2USBFido.isCandidateSlot("TOKEN2 FIDO2 Security Key(0024) 0"))
        XCTAssertTrue(Token2USBFido.isCandidateSlot("Token2 FIDO2 Security Key(0026)"))
        XCTAssertFalse(Token2USBFido.isCandidateSlot("Yubico YubiKey OTP+FIDO+CCID"))
        XCTAssertFalse(Token2USBFido.isCandidateSlot(nil))
    }

    func testIdentifySendsSelectThenTunnelGetInfo() async {
        let key = FakeKey([(Data("1000".utf8), 0x9000), (getInfoReply, 0x9000)])
        let ok = await Token2USBFido(exchange: key.exchange()).identify()
        XCTAssertTrue(ok)
        XCTAssertEqual(key.sent, [select, Data([0x80, 0xC5, 0x03, 0x00, 0x04])])
    }

    func testIdentifyRejectsNonToken2() async {
        let key = FakeKey([(Data(), 0x6A82)])
        let ok = await Token2USBFido(exchange: key.exchange()).identify()
        XCTAssertFalse(ok)
        XCTAssertEqual(key.sent.count, 1)
    }

    func testIdentifyRejectsTunnelWithoutCtap() async {
        let key = FakeKey([(Data("1000".utf8), 0x9000), (Data(), 0x6D00)])
        let ok = await Token2USBFido(exchange: key.exchange()).identify()
        XCTAssertFalse(ok)
    }

    func testAlphanumericMinPinUsesVendorHeaderAndKeepsBody() async throws {
        let key = FakeKey([(Data([0x00]), 0x9000)])
        let body = Data([0x0D, 0xA4, 0x01, 0x03, 0x02, 0xA1, 0x01, 0x0C])
        let r = try await Token2USBFido(exchange: key.exchange()).alphanumericMinPinConfig(body: body)
        XCTAssertEqual(r, Data([0x00]))
        XCTAssertEqual(key.sent, [Data([0x80, 0xC5, 0x02, 0x0A]) + body])
    }

    func testStatusWordErrorsSurface() async {
        let key = FakeKey([(Data(), 0x6982)])
        do {
            _ = try await Token2USBFido(exchange: key.exchange()).ctap(command: 0x04, cbor: Data())
            XCTFail("expected error")
        } catch {
            XCTAssertEqual(error as? Token2USBFido.LinkError, .status(0x6982))
        }
    }
}
