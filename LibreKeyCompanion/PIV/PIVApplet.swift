import Foundation
#if canImport(Security)
import Security
#endif
import CryptoKit

/// PIV (NIST SP 800-73-4) READ-ONLY status client.
///
/// Ported from the Android `piv/PivApplet.kt`. Reports applet version, which of
/// the standard key slots (9A/9C/9D/9E) hold a certificate, PIN/PUK retry counts,
/// and the card GUID. Certificate details are extracted via iOS `SecCertificate`
/// (cleaner than porting the ASN.1 parser): subject summary + SHA-256 fingerprint.
///
/// NOT implemented (security-critical, out of scope for a read build): GENERAL
/// AUTHENTICATE, key generation, certificate import, PIN/PUK change.
final class PIVApplet {
    private let transport: KeyTransport
    init(transport: KeyTransport) { self.transport = transport }

    static let AID = Data([0xA0, 0x00, 0x00, 0x03, 0x08])
    private static let INS_GET_DATA: UInt8 = 0xCB
    private static let INS_VERIFY: UInt8 = 0x20
    private static let INS_GET_VERSION: UInt8 = 0xFD   // YubiKey vendor extension

    private static let SLOT_OBJECTS: [(String, Data)] = [
        ("9A Authentication", Data([0x5F, 0xC1, 0x05])),
        ("9C Signature",      Data([0x5F, 0xC1, 0x0A])),
        ("9D Key Management", Data([0x5F, 0xC1, 0x0B])),
        ("9E Card Auth",      Data([0x5F, 0xC1, 0x01])),
    ]
    private static let CHUID_OBJECT = Data([0x5F, 0xC1, 0x02])
    private static let PIN_REF: UInt8 = 0x80
    private static let PUK_REF: UInt8 = 0x81

    struct CertInfo {
        let subjectSummary: String?
        let sha256Fingerprint: String
    }
    struct SlotCert {
        let slot: String
        let info: CertInfo
    }
    struct PIVStatus {
        let version: String?
        let slotsWithCert: [String]
        let certs: [SlotCert]
        let pinRetries: Int?
        let pukRetries: Int?
        let cardGuidHex: String?
    }

    func select() async throws { try await transport.selectApplet(aid: PIVApplet.AID) }

    func isPresent() async -> Bool {
        do { try await select(); return true } catch { return false }
    }

    func status() async throws -> PIVStatus {
        try await select()

        // Version (YubiKey vendor command; optional).
        var version: String?
        if let r = try? await transport.transmit(APDU(cla: 0x00, ins: PIVApplet.INS_GET_VERSION, p1: 0x00, p2: 0x00, le: 256)),
           r.isSuccess, r.data.count >= 3 {
            version = "\(r.data[r.data.startIndex]).\(r.data[r.data.startIndex+1]).\(r.data[r.data.startIndex+2])"
        }

        var present: [String] = []
        var certs: [SlotCert] = []
        for (label, objId) in PIVApplet.SLOT_OBJECTS {
            guard let raw = try? await getObject(objId), !raw.isEmpty else { continue }
            present.append(label)
            if let der = extractCertDer(raw), let info = parseCert(der) {
                certs.append(SlotCert(slot: label, info: info))
            }
        }

        let pin = try? await readRetries(PIVApplet.PIN_REF)
        let puk = try? await readRetries(PIVApplet.PUK_REF)
        let guid = try? await readCardGuid()

        return PIVStatus(version: version, slotsWithCert: present, certs: certs,
                         pinRetries: pin ?? nil, pukRetries: puk ?? nil, cardGuidHex: guid ?? nil)
    }

    /// GET DATA for a PIV object id (value inside the 0x53 wrapper).
    private func getObject(_ objId: Data) async throws -> Data {
        var tlv = Data([0x5C, UInt8(objId.count)]); tlv.append(objId)
        let resp = try await transport.transmit(APDU(cla: 0x00, ins: PIVApplet.INS_GET_DATA, p1: 0x3F, p2: 0xFF, data: tlv, le: 256))
        return resp.isSuccess ? resp.data : Data()
    }

    /// From a PIV data object (0x53 { 0x70 cert, ... }), pull the 0x70 DER.
    private func extractCertDer(_ data: Data) -> Data? {
        let body = PivTlv.valueOf(data, tag: 0x53) ?? data
        return PivTlv.valueOf(body, tag: 0x70)
    }

    /// VERIFY with empty data returns remaining tries in the status word.
    private func readRetries(_ ref: UInt8) async throws -> Int? {
        let r = try await transport.transmit(APDU(cla: 0x00, ins: PIVApplet.INS_VERIFY, p1: 0x00, p2: ref, le: 0))
        let sw = r.sw
        switch sw {
        case 0x9000: return nil                      // already verified
        case let s where (s & 0xFFF0) == 0x63C0: return Int(s & 0x000F)
        case 0x6983: return 0                          // blocked
        default: return nil
        }
    }

    /// CHUID (5FC102) contains a GUID in TLV 0x34.
    private func readCardGuid() async throws -> String? {
        let chuid = try await getObject(PIVApplet.CHUID_OBJECT)
        if chuid.isEmpty { return nil }
        let body = PivTlv.valueOf(chuid, tag: 0x53) ?? chuid
        guard let guid = PivTlv.valueOf(body, tag: 0x34) else { return nil }
        return guid.map { String(format: "%02X", $0) }.joined()
    }

    /// Parse a DER certificate via SecCertificate (subject summary) + SHA-256.
    private func parseCert(_ der: Data) -> CertInfo? {
        let fp = Data(SHA256.hash(data: der)).map { String(format: "%02x", $0) }.joined()
        var summary: String?
        #if canImport(Security)
        if let cert = SecCertificateCreateWithData(nil, der as CFData) {
            summary = SecCertificateCopySubjectSummary(cert) as String?
        }
        #endif
        return CertInfo(subjectSummary: summary, sha256Fingerprint: fp)
    }
}

/// Tiny flat TLV helper for PIV wrappers (single-byte + long-form lengths).
enum PivTlv {
    static func valueOf(_ data: Data, tag: Int) -> Data? {
        let b = [UInt8](data)
        var i = 0
        while i < b.count {
            let t = Int(b[i]); i += 1
            if i >= b.count { break }
            var len = Int(b[i]); i += 1
            if len & 0x80 != 0 {
                let n = len & 0x7F
                len = 0
                for _ in 0..<n { if i < b.count { len = (len << 8) | Int(b[i]); i += 1 } }
            }
            if i + len > b.count { break }
            if t == tag { return Data(b[i..<i+len]) }
            i += len
        }
        return nil
    }
}
