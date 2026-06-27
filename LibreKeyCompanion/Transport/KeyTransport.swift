import Foundation

/// Errors surfaced by any transport or applet operation.
public enum KeyError: Error, LocalizedError {
    case notConnected
    case transportFailed(String)
    case unexpectedStatus(UInt16)
    case appletNotPresent(String)
    case parsing(String)
    case unsupportedOnPlatform(String)
    case userCancelled
    /// The key needs a physical button touch to complete this read.
    case buttonPressRequired

    public var errorDescription: String? {
        switch self {
        case .notConnected:
            return "No security key is connected."
        case .transportFailed(let m):
            return "Transport error: \(m)"
        case .unexpectedStatus(let sw):
            return String(format: "Key returned status 0x%04X", sw)
        case .appletNotPresent(let name):
            return "\(name) applet is not present on this key."
        case .parsing(let m):
            return "Could not parse response: \(m)"
        case .unsupportedOnPlatform(let m):
            return m
        case .userCancelled:
            return "Cancelled."
        case .buttonPressRequired:
            return "Touch the key's button while holding it to the phone to reveal this code."
        }
    }
}

/// A live channel to a security key over which APDUs can be exchanged.
///
/// Two concrete conformers on iOS: `NFCTransport` (CoreNFC, all applets) and
/// `CCIDTransport` (CryptoTokenKit over USB-C, for the CCID-interface applets —
/// OATH, Token2 OTP, PIV, OpenPGP). FIDO2 uses the key's CTAPHID interface, which
/// iOS does not expose to third-party apps, so FIDO2 remains NFC-only. Applet
/// code stays transport-agnostic, exactly as in the original.
public protocol KeyTransport: AnyObject {
    var isConnected: Bool { get }
    /// Send one command APDU and await the response, transparently chaining
    /// GET RESPONSE (0x61xx) so callers receive the full payload.
    func transmit(_ apdu: APDU) async throws -> APDUResponse
}

/// A transport with a connect/teardown lifecycle (NFC session or USB session),
/// so callers can manage either uniformly.
public protocol ManagedTransport: KeyTransport {
    func connect() async throws
    func invalidate(message: String?)
}

public extension KeyTransport {
    /// SELECT by AID (ISO 7816-4, INS 0xA4, P1 0x04). Used to activate an applet.
    @discardableResult
    func selectApplet(aid: Data) async throws -> APDUResponse {
        let select = APDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: aid, le: 256)
        let resp = try await transmit(select)
        guard resp.isSuccess else { throw KeyError.unexpectedStatus(resp.sw) }
        return resp
    }
}
