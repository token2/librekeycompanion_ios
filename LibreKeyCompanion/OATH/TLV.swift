import Foundation

/// A single tag-length-value record.
public struct TLV {
    public let tag: UInt8
    public let value: Data
}

public extension TLV {
    /// Encode one simple-TLV with a 1-byte tag. Lengths ≥ 0x80 use the
    /// ISO 7816 long form (0x81 ll, or 0x82 ll ll).
    static func encode(tag: UInt8, value: Data) -> Data {
        var out = Data([tag])
        let len = value.count
        if len < 0x80 {
            out.append(UInt8(len))
        } else if len < 0x100 {
            out.append(0x81); out.append(UInt8(len))
        } else {
            out.append(0x82)
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        }
        out.append(value)
        return out
    }

    /// Parse a flat sequence of simple-TLV records (single-byte tags).
    /// Sufficient for the YKOATH and Token2 OTP responses.
    static func parse(_ data: Data) -> [TLV] {
        var out: [TLV] = []
        var i = data.startIndex
        while i < data.endIndex {
            let tag = data[i]
            i = data.index(after: i)
            guard i < data.endIndex else { break }
            var len = Int(data[i]); i = data.index(after: i)
            if len == 0x81, i < data.endIndex {
                len = Int(data[i]); i = data.index(after: i)
            } else if len == 0x82, data.distance(from: i, to: data.endIndex) >= 2 {
                len = Int(data[i]) << 8; i = data.index(after: i)
                len |= Int(data[i]); i = data.index(after: i)
            }
            let end = data.index(i, offsetBy: len, limitedBy: data.endIndex) ?? data.endIndex
            // Re-base to a fresh 0-indexed Data. Slicing keeps the parent's
            // indices, so `value[0]` on a slice would read the wrong offset (or
            // trap). Copying normalizes indices to start at 0.
            out.append(TLV(tag: tag, value: Data(data[i..<end])))
            i = end
        }
        return out
    }
}
