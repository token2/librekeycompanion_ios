import Foundation
#if canImport(CoreNFC)
import CoreNFC

/// NFC transport built on CoreNFC's `NFCTagReaderSession` + `NFCISO7816Tag`.
///
/// This is the iOS replacement for the Android app's `IsoDep` NFC path. It is
/// the *only* transport available on iOS: Apple does not expose arbitrary USB
/// CCID smart-card access to third-party apps, so the USB transport from the
/// original cannot be reproduced here.
///
/// Requirements to actually run on device:
///   • A paid Apple Developer account.
///   • The "Near Field Communication Tag Reading" capability.
///   • `com.apple.developer.nfc.readersession.iso7816.select-identifiers`
///     in the entitlements listing every AID this app SELECTs, plus the
///     `NFCReaderUsageDescription` Info.plist string.
///
/// CoreNFC requires you to declare, up front, the AIDs you intend to talk to.
/// That list lives in `Entitlements` below and must stay in sync with the AIDs
/// in the applet modules.
public final class NFCTransport: NSObject, ManagedTransport {

    /// Every AID the app may SELECT. CoreNFC matches tags against these.
    public enum AID {
        public static let oath      = Data([0xA0,0x00,0x00,0x05,0x27,0x21,0x01])           // YKOATH
        public static let fido      = Data([0xA0,0x00,0x00,0x06,0x47,0x2F,0x00,0x01])       // FIDO/U2F/CTAP
        public static let openpgp   = Data([0xD2,0x76,0x00,0x01,0x24,0x01])                 // OpenPGP card
        public static let piv       = Data([0xA0,0x00,0x00,0x03,0x08])                      // PIV (NIST 800-73)
        public static let token2otp = Data([0xF0,0x00,0x00,0x01,0x4F,0x74,0x70,0x01])        // Token2 on-device OTP management applet

        public static let all: [Data] = [oath, fido, openpgp, piv, token2otp]
    }

    private var session: NFCTagReaderSession?
    private var connectedTag: NFCISO7816Tag?
    private var connectionContinuation: CheckedContinuation<Void, Error>?

    public private(set) var isConnected: Bool = false

    /// Prompt shown in the system NFC sheet.
    public var alertMessage: String = "Hold your security key near the top of the phone."

    public override init() { super.init() }

    /// Begin a reader session and suspend until a key is tapped and connected,
    /// or the session fails / is cancelled.
    public func connect() async throws {
        guard NFCTagReaderSession.readingAvailable else {
            throw KeyError.unsupportedOnPlatform("This device does not support NFC tag reading.")
        }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            self.connectionContinuation = cont
            let s = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            s?.alertMessage = self.alertMessage
            self.session = s
            s?.begin()
        }
    }

    public func invalidate(message: String? = nil) {
        if let message { session?.alertMessage = message }
        session?.invalidate()
        session = nil
        connectedTag = nil
        isConnected = false
    }

    public func transmit(_ apdu: APDU) async throws -> APDUResponse {
        guard let tag = connectedTag else { throw KeyError.notConnected }
        var accumulated = Data()
        var current = apdu

        while true {
            let resp = try await sendOne(current, to: tag)
            accumulated.append(resp.data)

            if resp.hasMoreData {
                // GET RESPONSE: INS 0xC0, Le = SW2.
                current = APDU(cla: 0x00, ins: 0xC0, p1: 0x00, p2: 0x00,
                               data: Data(), le: resp.remainingBytes == 0 ? 256 : resp.remainingBytes)
                continue
            }
            return APDUResponse(data: accumulated, sw1: resp.sw1, sw2: resp.sw2)
        }
    }

    private func sendOne(_ apdu: APDU, to tag: NFCISO7816Tag) async throws -> APDUResponse {
        guard let cmd = NFCISO7816APDU(data: apdu.encoded()) else {
            throw KeyError.transportFailed("Malformed APDU.")
        }
        return try await withCheckedThrowingContinuation { cont in
            tag.sendCommand(apdu: cmd) { payload, sw1, sw2, error in
                if let error {
                    cont.resume(throwing: KeyError.transportFailed(error.localizedDescription))
                } else {
                    cont.resume(returning: APDUResponse(data: payload, sw1: sw1, sw2: sw2))
                }
            }
        }
    }
}

extension NFCTransport: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) { }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        isConnected = false
        connectedTag = nil
        self.session = nil
        if let cont = connectionContinuation {
            connectionContinuation = nil
            let nfcErr = error as? NFCReaderError
            if nfcErr?.code == .readerSessionInvalidationErrorUserCanceled {
                cont.resume(throwing: KeyError.userCancelled)
            } else {
                cont.resume(throwing: KeyError.transportFailed(error.localizedDescription))
            }
        }
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let first = tags.first, case let .iso7816(isoTag) = first else {
            session.invalidate(errorMessage: "Unsupported tag. Tap a FIDO/smart-card key.")
            return
        }
        session.connect(to: first) { [weak self] error in
            guard let self else { return }
            if let error {
                session.invalidate(errorMessage: error.localizedDescription)
                return
            }
            self.connectedTag = isoTag
            self.isConnected = true
            if let cont = self.connectionContinuation {
                self.connectionContinuation = nil
                cont.resume()
            }
        }
    }
}
#endif
