import Foundation

/// One FIDO Alliance Metadata Service entry, flattened to the shape the app uses
/// (`{ aaguid, description, icon, status }`), matching the Android bundled file.
struct MDSEntry: Codable, Identifiable, Sendable {
    let aaguid: String
    let description: String
    let icon: String?         // data: URI
    let status: String?       // e.g. "FIDO_CERTIFIED_L2"
    var id: String { aaguid }

    /// Decode the `data:image/...;base64,...` icon URI into raw image bytes.
    var iconData: Data? {
        guard let uri = icon, let comma = uri.firstIndex(of: ",") else { return nil }
        let header = uri[uri.startIndex..<comma]
        guard header.contains("base64") else { return nil }
        let b64 = String(uri[uri.index(after: comma)...])
        return Data(base64Encoded: b64)
    }

    /// Full certification badge label, e.g. "FIDO Certified L2", or
    /// "FIDO Certified" for a level-less certification. nil if not certified.
    var certBadge: String? {
        guard let s = status, s.hasPrefix("FIDO_CERTIFIED") else { return nil }
        if let r = s.range(of: "_L") {
            let level = s[r.upperBound...]          // e.g. "2", "1_PLUS"
            // Normalize "1_PLUS" → "1+", keep plain digits as-is.
            let pretty = level.replacingOccurrences(of: "_PLUS", with: "+")
            return "FIDO Certified L\(pretty)"
        }
        return "FIDO Certified"
    }
}

/// FIDO Metadata Service (MDS) lookup + in-app update.
///
/// Ported from the Android `fido/MdsRepository.kt`. Two data sources, tried in
/// order: a user-updated cache (downloaded from the FIDO Alliance MDS3 endpoint
/// and stored in Documents), then the bundled starter set so lookups work
/// offline. The live MDS3 BLOB is a JWT whose middle segment is base64url JSON
/// with an `entries` array; we decode and parse that, plus the flat-array and
/// `{entries:{…}}` shapes.
@MainActor
final class MDSRepository: ObservableObject {
    @Published private(set) var entryCount = 0
    @Published private(set) var sourceLabel = "none"      // "downloaded" | "bundled" | "none"
    @Published private(set) var lastUpdated: Date?
    @Published private(set) var isFetching = false
    @Published private(set) var lastError: String?

    private var map: [String: MDSEntry] = [:]

    static let mds3URL = URL(string: "https://mds3.fidoalliance.org/")!

    private var cacheURL: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("mds_cache.json")
    }

    init() { load() }

    /// Load the best available source into memory: cache first, then bundled.
    func load() {
        let fm = FileManager.default
        if fm.fileExists(atPath: cacheURL.path),
           let text = try? String(contentsOf: cacheURL, encoding: .utf8),
           let parsed = try? Self.parseAny(text), !parsed.isEmpty {
            map = parsed
            sourceLabel = "downloaded"
            entryCount = parsed.count
            lastUpdated = (try? fm.attributesOfItem(atPath: cacheURL.path)[.modificationDate]) as? Date
            return
        }
        if let url = Bundle.main.url(forResource: "mds_bundled", withExtension: "json"),
           var text = try? String(contentsOf: url, encoding: .utf8) {
            text = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !text.hasPrefix("{"), !text.hasPrefix("["), text.filter({ $0 == "." }).count >= 2 {
                text = (try? Self.decodeJwtClaims(text)) ?? text
            }
            if let parsed = try? Self.parseAny(text) {
                map = parsed; sourceLabel = "bundled"; entryCount = parsed.count; lastUpdated = nil
                return
            }
        }
        map = [:]; sourceLabel = "none"; entryCount = 0
    }

    /// Look up an authenticator by AAGUID (hex, with or without dashes).
    func lookup(aaguid: String?) -> MDSEntry? {
        guard let a = aaguid, !a.isEmpty else { return nil }
        return map[Self.normalize(a)]
    }

    /// Fetch the live MDS3 BLOB, parse it, persist a normalized cache, reload.
    func updateFromFido() async {
        isFetching = true; lastError = nil
        defer { isFetching = false }
        do {
            let (data, response) = try await URLSession.shared.data(from: Self.mds3URL)
            if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                lastError = "Server returned HTTP \(http.statusCode)."
                return
            }
            guard let text = String(data: data, encoding: .utf8) else {
                lastError = "Couldn't decode the metadata response."
                return
            }
            let count = try await saveFetched(text)
            if count == 0 { lastError = "Couldn't parse the metadata blob." }
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Save a freshly-fetched MDS payload (raw JWT BLOB or JSON) and reload.
    /// The heavy decode/parse/serialize runs off the main actor so a multi-MB
    /// blob never freezes the UI; only the small state updates happen on main.
    @discardableResult
    func saveFetched(_ payload: String) async throws -> Int {
        let cacheURL = self.cacheURL
        // Do the expensive work on a background task.
        let result: (map: [String: MDSEntry], json: String)? = try await Task.detached(priority: .userInitiated) {
            let t = payload.trimmingCharacters(in: .whitespaces)
            let json: String
            if !t.hasPrefix("{"), !t.hasPrefix("["), t.filter({ $0 == "." }).count >= 2 {
                json = try Self.decodeJwtClaims(payload)
            } else {
                json = payload
            }
            let parsed = try Self.parseAny(json)
            guard !parsed.isEmpty else { return nil }
            let serialized = try Self.toBundledJson(parsed)
            try serialized.write(to: cacheURL, atomically: true, encoding: .utf8)
            return (parsed, serialized)
        }.value

        guard let result else { return 0 }
        // Back on the main actor: publish the new data.
        map = result.map
        sourceLabel = "downloaded"
        entryCount = result.map.count
        lastUpdated = Date()
        return result.map.count
    }

    // ---- parsing ----

    nonisolated private static func parseAny(_ text: String) throws -> [String: MDSEntry] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = trimmed.data(using: .utf8) else { return [:] }
        let obj = try JSONSerialization.jsonObject(with: data)
        if let arr = obj as? [[String: Any]] { return parseFlatArray(arr) }
        if let dict = obj as? [String: Any] {
            if let entriesArr = dict["entries"] as? [[String: Any]] { return parseBlob(entriesArr) }
            if let entriesMap = dict["entries"] as? [String: Any] { return parseBundledMap(entriesMap) }
        }
        return [:]
    }

    /// Flat array: [{aaguid, description, icon, status}, …] (bundled file shape).
    nonisolated private static func parseFlatArray(_ arr: [[String: Any]]) -> [String: MDSEntry] {
        var out: [String: MDSEntry] = [:]
        for e in arr {
            guard let aaguid = e["aaguid"] as? String else { continue }
            let n = normalize(aaguid)
            out[n] = MDSEntry(aaguid: n,
                              description: e["description"] as? String ?? "Unknown authenticator",
                              icon: e["icon"] as? String,
                              status: e["status"] as? String)
        }
        return out
    }

    /// Official MDS3 BLOB entries array: each has metadataStatement + statusReports.
    nonisolated private static func parseBlob(_ entries: [[String: Any]]) -> [String: MDSEntry] {
        var out: [String: MDSEntry] = [:]
        for e in entries {
            guard let ms = e["metadataStatement"] as? [String: Any] else { continue }
            guard let aaguid = (e["aaguid"] as? String) ?? (ms["aaguid"] as? String) else { continue }
            let name = ms["description"] as? String ?? "Unknown authenticator"
            let icon = ms["icon"] as? String
            var cert: String?
            if let reports = e["statusReports"] as? [[String: Any]] {
                for r in reports {
                    guard let s = r["status"] as? String, s.hasPrefix("FIDO_CERTIFIED") else { continue }
                    // Prefer a level-bearing status (…_L1/_L2/_L3) over a bare
                    // "FIDO_CERTIFIED". Among levelled ones, keep the highest.
                    cert = preferredCert(cert, s)
                }
            }
            let n = normalize(aaguid)
            out[n] = MDSEntry(aaguid: n, description: name, icon: icon, status: cert)
        }
        return out
    }

    /// Rank two FIDO_CERTIFIED status strings and return the more specific one.
    /// A levelled status (e.g. FIDO_CERTIFIED_L2) outranks a bare FIDO_CERTIFIED,
    /// and a higher level outranks a lower one. Used so a later, non-levelled
    /// status report doesn't clobber the certification level.
    nonisolated private static func preferredCert(_ current: String?, _ candidate: String) -> String {
        func rank(_ s: String?) -> Int {
            guard let s, s.hasPrefix("FIDO_CERTIFIED") else { return -1 }
            if let r = s.range(of: "_L"),
               let level = Int(s[r.upperBound...].prefix(1)) {
                return 10 + level          // levelled: 11, 12, 13…
            }
            return 0                       // bare FIDO_CERTIFIED
        }
        return rank(candidate) >= rank(current) ? candidate : (current ?? candidate)
    }

    /// Simple {entries:{aaguid:{name,certification,icon}}} shape.
    nonisolated private static func parseBundledMap(_ entries: [String: Any]) -> [String: MDSEntry] {
        var out: [String: MDSEntry] = [:]
        for (k, v) in entries {
            guard let obj = v as? [String: Any] else { continue }
            let n = normalize(k)
            out[n] = MDSEntry(aaguid: n,
                              description: obj["name"] as? String ?? "Unknown authenticator",
                              icon: obj["icon"] as? String,
                              status: obj["certification"] as? String)
        }
        return out
    }

    /// Serialize in the flat-array shape used by the bundled file.
    nonisolated private static func toBundledJson(_ m: [String: MDSEntry]) throws -> String {
        let arr: [[String: Any]] = m.values.map { e in
            var d: [String: Any] = ["aaguid": e.aaguid, "description": e.description]
            if let i = e.icon { d["icon"] = i }
            if let s = e.status { d["status"] = s }
            return d
        }
        let data = try JSONSerialization.data(withJSONObject: arr)
        return String(data: data, encoding: .utf8) ?? "[]"
    }

    nonisolated private static func decodeJwtClaims(_ jwt: String) throws -> String {
        let parts = jwt.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ".")
        guard parts.count >= 2 else { throw KeyError.parsing("Not a JWT") }
        var b64 = String(parts[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }       // restore padding
        guard let data = Data(base64Encoded: b64), let text = String(data: data, encoding: .utf8) else {
            throw KeyError.parsing("Couldn't decode JWT claims")
        }
        return text
    }

    nonisolated private static func normalize(_ aaguid: String) -> String {
        aaguid.lowercased().replacingOccurrences(of: "-", with: "").trimmingCharacters(in: .whitespaces)
    }
}
