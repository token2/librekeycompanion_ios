import Foundation

/// OpenPGP Card v3.4 READ-ONLY status client.
///
/// Ported from the Android `openpgp/OpenPgpApplet.kt`. Reads Application Related
/// Data (0x6E) and Cardholder Related Data (0x65) via GET DATA, parses BER-TLV,
/// and surfaces a non-sensitive summary: per-slot key presence/algorithm/date/
/// fingerprint, PW1/PW3 retry counts, cardholder, URL, serial.
///
/// NOT implemented (security-critical): key generation/import, PSO:CDS signing,
/// PSO:DEC decryption, PIN verification, factory reset.
final class OpenPGPApplet {
    private let transport: KeyTransport
    init(transport: KeyTransport) { self.transport = transport }

    static let AID = Data([0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
    private static let INS_GET_DATA: UInt8 = 0xCA
    private static let DO_APPLICATION_RELATED = 0x006E
    private static let DO_CARDHOLDER_RELATED = 0x0065
    private static let DO_URL = 0x5F50

    struct KeySlot {
        let name: String          // "Signature", "Decryption", "Authentication"
        let present: Bool
        let fingerprint: String?
        let algorithm: String?
        let generated: String?
    }
    struct CardStatus {
        let specVersion: String
        let cardholderName: String?
        let url: String?
        let keys: [KeySlot]
        let pin1Retries: Int?
        let pin3Retries: Int?
        let serialHex: String?
    }

    func select() async throws { try await transport.selectApplet(aid: OpenPGPApplet.AID) }

    func isPresent() async -> Bool {
        do { try await select(); return true } catch { return false }
    }

    func status() async throws -> CardStatus {
        try await select()
        let appData = try? await getData(OpenPGPApplet.DO_APPLICATION_RELATED)
        let cardholder = try? await getData(OpenPGPApplet.DO_CARDHOLDER_RELATED)
        let urlBytes = try? await getData(OpenPGPApplet.DO_URL)

        let tree = appData.flatMap { BerTlv.parse($0) }
        let fingerprints = tree?.find(0x00C5)     // 60 bytes: 3 × 20
        let timestamps = tree?.find(0x00CD)       // 12 bytes: 3 × 4 (epoch seconds)
        let pwStatus = tree?.find(0x00C4)
        let aid = tree?.find(0x004F)

        let slotNames = ["Signature", "Decryption", "Authentication"]
        let algoTags = [0x00C1, 0x00C2, 0x00C3]
        var keys: [KeySlot] = []
        for idx in 0..<3 {
            let fp: Data? = fingerprints.flatMap { $0.count >= (idx+1)*20 ? $0.subdata(in: idx*20..<idx*20+20) : nil }
            let present = (fp?.contains { $0 != 0 }) ?? false
            let ts: Data? = timestamps.flatMap { $0.count >= (idx+1)*4 ? $0.subdata(in: idx*4..<idx*4+4) : nil }
            keys.append(KeySlot(
                name: slotNames[idx],
                present: present,
                fingerprint: present ? fp!.map { String(format: "%02X", $0) }.joined() : nil,
                algorithm: tree?.find(algoTags[idx]).map { algorithmName($0) },
                generated: present ? ts.flatMap { epochToDate($0) } : nil))
        }

        // PW status: [4]=PW1 tries, [6]=PW3 tries.
        let pin1 = (pwStatus.flatMap { $0.count >= 7 ? Int($0[$0.startIndex+4]) : nil })
        let pin3 = (pwStatus.flatMap { $0.count >= 7 ? Int($0[$0.startIndex+6]) : nil })
        let serial = aid.flatMap { $0.count >= 14 ? $0.subdata(in: 10..<14).map { String(format: "%02X", $0) }.joined() : nil }
        let name = cardholder.flatMap { BerTlv.parse($0)?.find(0x005B) }.flatMap { String(data: $0, encoding: .utf8) }
        let url = urlBytes.flatMap { String(data: $0, encoding: .utf8) }

        return CardStatus(
            specVersion: "3.4 (declared)",
            cardholderName: name,
            url: url,
            keys: keys,
            pin1Retries: pin1,
            pin3Retries: pin3,
            serialHex: serial)
    }

    private func algorithmName(_ attr: Data) -> String {
        guard !attr.isEmpty else { return "?" }
        let b = [UInt8](attr)
        switch Int(b[0]) {
        case 0x01:
            if b.count >= 3 { return "RSA \((Int(b[1]) << 8) | Int(b[2]))" }
            return "RSA"
        case 0x12: return "ECDH " + curveFromOid(b)
        case 0x13: return "ECDSA " + curveFromOid(b)
        case 0x16: return "EdDSA " + curveFromOid(b)
        default: return String(format: "alg 0x%02X", b[0])
        }
    }

    private func curveFromOid(_ b: [UInt8]) -> String {
        guard b.count >= 2 else { return "" }
        let oid = Array(b[1...])
        func eq(_ vals: [UInt8]) -> Bool { oid.count >= vals.count && Array(oid[0..<vals.count]) == vals }
        if eq([0x2B,0x06,0x01,0x04,0x01,0xDA,0x47,0x0F,0x01]) { return "Ed25519" }
        if eq([0x2B,0x06,0x01,0x04,0x01,0x97,0x55,0x01,0x05,0x01]) { return "Curve25519" }
        if eq([0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07]) { return "P-256" }
        if eq([0x2B,0x81,0x04,0x00,0x22]) { return "P-384" }
        if eq([0x2B,0x81,0x04,0x00,0x23]) { return "P-521" }
        return "(curve?)"
    }

    private func epochToDate(_ b: Data) -> String? {
        guard b.count >= 4 else { return nil }
        let bytes = [UInt8](b)
        let secs = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        if secs == 0 { return nil }
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd"; df.timeZone = TimeZone(identifier: "UTC")
        return df.string(from: Date(timeIntervalSince1970: TimeInterval(secs)))
    }

    private func getData(_ tag: Int) async throws -> Data {
        let resp = try await transport.transmit(APDU(cla: 0x00, ins: OpenPGPApplet.INS_GET_DATA,
                                                     p1: UInt8((tag >> 8) & 0xFF), p2: UInt8(tag & 0xFF), le: 256))
        guard resp.isSuccess else { throw KeyError.unexpectedStatus(resp.sw) }
        return resp.data
    }
}

/// Minimal BER-TLV reader supporting 1- and 2-byte tags and short/long length.
enum BerTlv {
    final class Node {
        let tag: Int; let value: Data; let children: [Node]
        init(tag: Int, value: Data, children: [Node]) { self.tag = tag; self.value = value; self.children = children }
    }

    static func parse(_ data: Data) -> TlvTree? {
        TlvTree(roots: parseNodes([UInt8](data), 0, data.count))
    }

    private static func parseNodes(_ data: [UInt8], _ start: Int, _ end: Int) -> [Node] {
        var nodes: [Node] = []
        var i = start
        while i < end {
            if data[i] == 0x00 { i += 1; continue }       // padding
            var tag = Int(data[i]); i += 1
            if tag & 0x1F == 0x1F {                        // multi-byte tag
                if i >= end { break }
                tag = (tag << 8) | Int(data[i]); i += 1
                while i < end && (tag & 0x80) != 0 && (Int(data[i]) & 0x80) != 0 {
                    tag = (tag << 8) | Int(data[i]); i += 1
                }
            }
            if i >= end { break }
            var len = Int(data[i]); i += 1
            if len & 0x80 != 0 {                           // long form
                let n = len & 0x7F
                if n == 0 || i + n > end { break }
                len = 0
                for _ in 0..<n { len = (len << 8) | Int(data[i]); i += 1 }
            }
            if len < 0 || i + len > end { break }
            let value = Data(data[i..<i+len])
            let constructed = (tag & 0x20) != 0 || (tag > 0xFF && ((tag >> 8) & 0x20) != 0)
            let children = (constructed && !value.isEmpty) ? parseNodes([UInt8](value), 0, value.count) : []
            nodes.append(Node(tag: tag, value: value, children: children))
            i += len
        }
        return nodes
    }
}

struct TlvTree {
    let roots: [BerTlv.Node]
    func find(_ tag: Int) -> Data? { search(roots, tag) }
    private func search(_ nodes: [BerTlv.Node], _ tag: Int) -> Data? {
        for n in nodes {
            if n.tag == tag { return n.value }
            if let f = search(n.children, tag) { return f }
        }
        return nil
    }
}
