import Foundation
#if canImport(CryptoTokenKit)
import CryptoTokenKit
#endif

/// USB-C smart-card transport via CryptoTokenKit (`TKSmartCard`).
///
/// iOS 16.1+ exposes USB-CCID-class smart cards through CryptoTokenKit, letting a
/// third-party app send arbitrary APDUs — exactly what the CCID-interface applets
/// need (OATH, Token2 OTP, PIV, OpenPGP). FIDO2 management is NOT available here:
/// it rides the key's CTAPHID interface, which iOS doesn't expose. Use NFC for FIDO2.
///
/// The Android app used the raw USB Host API (`USB_DEVICE_ATTACHED` + bulk
/// transfer); on iOS the OS owns the CCID driver and we talk through `TKSmartCard`,
/// which is APDU-level only (no custom CCID framing). That's sufficient for the
/// ISO-7816 applets here.
public final class CCIDTransport: NSObject, ManagedTransport {
    #if canImport(CryptoTokenKit)
    private var slot: TKSmartCardSlot?
    private var card: TKSmartCard?
    #endif
    public private(set) var isConnected = false

    /// Whether CryptoTokenKit smart-card support exists on this device at all.
    public static var isAvailable: Bool {
        #if canImport(CryptoTokenKit)
        return TKSmartCardSlotManager.default != nil
        #else
        return false
        #endif
    }

    /// Names of currently-attached smart-card slots (USB readers / keys).
    public static var availableSlotNames: [String] {
        #if canImport(CryptoTokenKit)
        return TKSmartCardSlotManager.default?.slotNames ?? []
        #else
        return []
        #endif
    }

    /// Connect to the first slot that currently holds a card, open a session.
    /// Throws `unsupportedOnPlatform` if CryptoTokenKit isn't present, or
    /// `notConnected` if no USB key/reader with an inserted card is found.
    public func connect() async throws {
        #if canImport(CryptoTokenKit)
        guard let manager = TKSmartCardSlotManager.default else {
            throw KeyError.unsupportedOnPlatform("This device has no USB smart-card support.")
        }
        // Find a slot with a present card. Slots can momentarily report no card
        // right after attach, so resolve each slot then check its state.
        for name in manager.slotNames {
            guard let slot = await getSlot(manager, name: name) else { continue }
            if slot.state == .validCard, let card = slot.makeSmartCard() {
                let ok = try await beginSession(card)
                if ok {
                    self.slot = slot
                    self.card = card
                    self.isConnected = true
                    return
                }
            }
        }
        throw KeyError.notConnected
        #else
        throw KeyError.unsupportedOnPlatform("USB smart cards require CryptoTokenKit.")
        #endif
    }

    public func invalidate(message: String? = nil) {
        #if canImport(CryptoTokenKit)
        card?.endSession()
        #endif
        card = nil
        slot = nil
        isConnected = false
    }

    /// Send one command APDU, chaining GET RESPONSE (0x61xx) like the NFC path.
    public func transmit(_ apdu: APDU) async throws -> APDUResponse {
        #if canImport(CryptoTokenKit)
        guard let card else { throw KeyError.notConnected }
        var response = try await rawTransmit(card, apdu.encoded())

        // Chain GET RESPONSE when the card signals more data (61 xx).
        while response.count >= 2, response[response.count - 2] == 0x61 {
            let le = Int(response[response.count - 1])
            let getResponse = APDU(cla: 0x00, ins: 0xC0, p1: 0x00, p2: 0x00, le: le == 0 ? 256 : le)
            let next = try await rawTransmit(card, getResponse.encoded())
            // Concatenate payloads (drop the prior 61xx status), keep the new SW.
            response = response.dropLast(2) + next
        }
        return APDUResponse(raw: response)
        #else
        throw KeyError.unsupportedOnPlatform("USB smart cards require CryptoTokenKit.")
        #endif
    }

    // MARK: - async bridges over the callback API

    #if canImport(CryptoTokenKit)
    private func getSlot(_ manager: TKSmartCardSlotManager, name: String) async -> TKSmartCardSlot? {
        await withCheckedContinuation { cont in
            manager.getSlot(withName: name) { slot in cont.resume(returning: slot) }
        }
    }

    private func beginSession(_ card: TKSmartCard) async throws -> Bool {
        try await withCheckedThrowingContinuation { cont in
            card.beginSession { success, error in
                if let error { cont.resume(throwing: error) }
                else { cont.resume(returning: success) }
            }
        }
    }

    private func rawTransmit(_ card: TKSmartCard, _ command: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            card.transmit(command) { reply, error in
                if let error { cont.resume(throwing: error) }
                else if let reply { cont.resume(returning: reply) }
                else { cont.resume(throwing: KeyError.transportFailed("Empty CCID response")) }
            }
        }
    }
    #endif
}
