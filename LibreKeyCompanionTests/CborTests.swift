import XCTest
@testable import LibreKeyCompanion

/// Validates the CBOR codec against canonical RFC 7049 vectors and the CTAP
/// int-keyed map canonical ordering.
final class CborTests: XCTestCase {

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testUnsignedIntEncoding() {
        XCTAssertEqual(hex(Cbor.encode(.uint(0))), "00")
        XCTAssertEqual(hex(Cbor.encode(.uint(10))), "0a")
        XCTAssertEqual(hex(Cbor.encode(.uint(23))), "17")
        XCTAssertEqual(hex(Cbor.encode(.uint(24))), "1818")
        XCTAssertEqual(hex(Cbor.encode(.uint(100))), "1864")
        XCTAssertEqual(hex(Cbor.encode(.uint(1000))), "1903e8")
        XCTAssertEqual(hex(Cbor.encode(.uint(1000000))), "1a000f4240")
    }

    func testNegativeIntEncoding() {
        XCTAssertEqual(hex(Cbor.encode(.nint(-1))), "20")
        XCTAssertEqual(hex(Cbor.encode(.nint(-100))), "3863")
    }

    func testStringAndBytesEncoding() {
        XCTAssertEqual(hex(Cbor.encode(.text(""))), "60")
        XCTAssertEqual(hex(Cbor.encode(.text("a"))), "6161")
        XCTAssertEqual(hex(Cbor.encode(.text("IETF"))), "6449455446")
        XCTAssertEqual(hex(Cbor.encode(.bytes(Data([1,2,3,4])))), "4401020304")
    }

    func testCanonicalMapKeyOrdering() {
        // Provide keys out of order; canonical encoding must sort int keys ascending.
        // Expected: a2 01 6161 02 4101
        let map: [Cbor.MapKey: Cbor.Value] = [.int(2): .bytes(Data([1])), .int(1): .text("a")]
        XCTAssertEqual(hex(Cbor.encode(.map(map))), "a2016161024101")
    }

    func testDecodeRoundTrip() throws {
        let original: Cbor.Value = .map([.int(1): .text("a"), .int(2): .bytes(Data([1]))])
        let encoded = Cbor.encode(original)
        let decoded = try Cbor.decode(encoded)
        guard case .map(let m) = decoded else { return XCTFail("not a map") }
        XCTAssertEqual(m[.int(1)], .text("a"))
        XCTAssertEqual(m[.int(2)], .bytes(Data([1])))
    }

    func testDecodeNegativeInt() throws {
        XCTAssertEqual(try Cbor.decode(Data([0x20])), .nint(-1))
        XCTAssertEqual(try Cbor.decode(Data([0x38, 0x63])), .nint(-100))
    }
}
