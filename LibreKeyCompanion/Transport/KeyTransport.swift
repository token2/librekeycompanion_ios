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
    /// The OATH applet is password protected and no valid password is cached.
    /// Carries the device id, which is the salt for deriving the access key.
    case oathPasswordRequired(deviceId: Data)
    /// A VALIDATE attempt was rejected by the key.
    case oathPasswordIncorrect(deviceId: Data)
    // --- Token2 OTP PIN (privacy protection, firmware R3.4+) ---
    /// The OTP store is PIN-protected and no verify window is open.
    case otpPinNotVerified
    /// The OTP PIN is locked out; the only recovery is erasing all OTP profiles.
    case otpPinBlocked
    /// The command isn't allowed in the current PIN state (e.g. SET when set).
    case otpPinWrongState
    /// This key's firmware doesn't support the OTP PIN feature (pre-R3.4).
    case otpPinUnsupported(UInt16)
    /// §1.20 fingerprint-protected OTP — the on-key fingerprint check didn't pass.
    case otpFingerprintNotVerified(UInt16)
    /// Enabling FP protection was refused because no fingerprint is enrolled (0x6984).
    case otpNoFingerprintEnrolled

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
        case .oathPasswordRequired:
            return "This key's OATH accounts are protected by a password."
        case .oathPasswordIncorrect:
            return "The key rejected that OATH password."
        case .otpPinNotVerified:
            return "OTP PIN not verified or incorrect."
        case .otpPinBlocked:
            return "The OTP PIN is locked out. The only recovery is erasing all OTP profiles."
        case .otpPinWrongState:
            return "That command isn't allowed in the current PIN state."
        case .otpPinUnsupported(let sw):
            return String(format: "This key's firmware doesn't support the OTP PIN (0x%04X).", sw)
        case .otpFingerprintNotVerified:
            return "Fingerprint not verified. Touch the key's sensor with an enrolled finger and try again."
        case .otpNoFingerprintEnrolled:
            return "No fingerprint is enrolled on this key. Enroll one in the key's FIDO2 fingerprint setup first."
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
