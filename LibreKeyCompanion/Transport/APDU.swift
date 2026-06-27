import Foundation

/// ISO 7816-4 command APDU.
///
/// Mirrors the APDU construction used in the Android app's `transport/` package,
/// but expressed as a Swift value type. Extended-length encoding is supported so
/// long responses (e.g. PIV certificates) can be fetched in one shot where the
/// key allows it.
public struct APDU: Equatable {
    public var cla: UInt8
    public var ins: UInt8
    public var p1: UInt8
    public var p2: UInt8
    public var data: Data
    /// Expected response length. 0 means "no Le byte"; 256 maps to the short Le=0x00.
    public var le: Int
    /// Force ISO 7816 extended-length Lc encoding even for short/empty data.
    /// The Token2 applet requires `00 hi lo` Lc framing on every command.
    public var forceExtended: Bool

    public init(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: Data = Data(), le: Int = 256, forceExtended: Bool = false) {
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.le = le
        self.forceExtended = forceExtended
    }

    /// Encode to wire bytes. Uses extended-length fields when data or Le exceeds
    /// 255, or when `forceExtended` is set.
    public func encoded() -> Data {
        var out = Data([cla, ins, p1, p2])
        let lc = data.count
        let extended = forceExtended || lc > 255 || le > 256

        if extended {
            // Extended Lc is always 3 bytes (00 hi lo) when present. With
            // forceExtended we emit it even for empty data, matching the Token2
            // applet's framing.
            if lc > 0 || forceExtended {
                out.append(0x00)
                out.append(UInt8((lc >> 8) & 0xFF))
                out.append(UInt8(lc & 0xFF))
                out.append(data)
            }
            if le > 0 {
                if lc == 0 && !forceExtended { out.append(0x00) }
                let leVal = le == 65536 ? 0 : le
                out.append(UInt8((leVal >> 8) & 0xFF))
                out.append(UInt8(leVal & 0xFF))
            }
        } else {
            if lc > 0 {
                out.append(UInt8(lc))
                out.append(data)
            }
            if le > 0 {
                out.append(UInt8(le == 256 ? 0x00 : le))
            }
        }
        return out
    }
}

/// ISO 7816-4 response APDU: payload plus the two status bytes (SW1 SW2).
public struct APDUResponse {
    public let data: Data
    public let sw1: UInt8
    public let sw2: UInt8

    public init(raw: Data) {
        precondition(raw.count >= 2, "APDU response must contain at least SW1 SW2")
        self.sw1 = raw[raw.index(raw.endIndex, offsetBy: -2)]
        self.sw2 = raw[raw.index(raw.endIndex, offsetBy: -1)]
        self.data = raw.prefix(raw.count - 2)
    }

    public init(data: Data, sw1: UInt8, sw2: UInt8) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }

    public var sw: UInt16 { (UInt16(sw1) << 8) | UInt16(sw2) }
    public var isSuccess: Bool { sw == 0x9000 }
    /// True when SW1 == 0x61: more data available, retrievable with GET RESPONSE.
    public var hasMoreData: Bool { sw1 == 0x61 }
    /// When `hasMoreData`, the number of further bytes the card is offering.
    public var remainingBytes: Int { Int(sw2) }
}

public enum APDUStatus {
    public static let ok: UInt16 = 0x9000
    public static let moreData: UInt8 = 0x61
    public static let wrongLength: UInt16 = 0x6700
    public static let conditionsNotSatisfied: UInt16 = 0x6985
    public static let fileNotFound: UInt16 = 0x6A82
    public static let instructionNotSupported: UInt16 = 0x6D00
    /// SW returned by a CCID/CTAP applet when handed a FIDO command it won't service.
    public static let fidoNotOnThisInterface: UInt16 = 0x6A81
}
