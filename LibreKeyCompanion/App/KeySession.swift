import Foundation
import SwiftUI

/// Drives an NFC session and exposes results to SwiftUI.
///
/// On iOS every operation is one tap: CoreNFC sessions are short-lived and
/// foreground-only, so the UI pattern is "press a button → tap key → read →
/// session ends", unlike Android where a plugged USB key stays connected.
@MainActor
final class KeySession: ObservableObject {
    @Published var credentials: [LiveCode] = []
    @Published var statusMessage: String = "Ready. Tap a key to read its OTP codes."
    @Published var isScanning = false
    /// Non-nil while the app is waiting for a physical button press on the key
    /// (e.g. revealing a touch-required code over USB, where there's no NFC sheet).
    @Published var touchPrompt: String?
    @Published var errorMessage: String?

    /// Which OTP applet the last scan detected — routes add/delete correctly.
    enum OTPKind { case unknown, oath, token2 }
    @Published var detectedKind: OTPKind = .unknown

    /// Connection transport for CCID-interface applets (OATH, Token2, PIV, PGP).
    /// FIDO2 always uses NFC regardless (its HID interface isn't USB-reachable).
    enum TransportMode: String { case nfc, usb }
    @Published var transportMode: TransportMode = .nfc
    /// Whether a USB smart-card key is currently attached (for enabling the option).
    @Published var usbAvailable = false
    /// True when a USB card is plugged in and readable — tabs observe this to
    /// auto-read on attach instead of waiting for a button tap.
    @Published var usbCardReady = false

    private let usbMonitor = USBMonitor()

    /// Begin watching for USB key attachment. When a card becomes ready, switch to
    /// USB mode and flag `usbCardReady` so the active tab can auto-read.
    func startUSBMonitoring() {
        usbMonitor.onCardReady = { [weak self] in
            guard let self else { return }
            self.transportMode = .usb
            self.usbCardReady = true
        }
        usbMonitor.onAttachChange = { [weak self] attached in
            self?.usbAvailable = attached
            if !attached {
                // Key unplugged — revert to NFC, clear any pending auto-read, and
                // wipe the displayed data (same as starting a fresh read) so the
                // screen doesn't show codes for a key that's no longer present.
                self?.transportMode = .nfc
                self?.usbCardReady = false
                self?.clearKeyData()
                self?.infoScanned = false
                self?.oathPresent = nil; self?.token2Present = nil; self?.fidoPresent = nil
                self?.pivStatus = nil; self?.pgpStatus = nil
                self?.pivAbsent = false; self?.pgpAbsent = false
            }
        }
        usbMonitor.start()
    }
    func stopUSBMonitoring() { usbMonitor.stop() }
    /// Tabs call this after consuming an auto-read trigger.
    func clearUSBReadyFlag() { usbCardReady = false }

    /// Make a connected transport for CCID-capable operations, honoring the user's
    /// NFC/USB choice. Falls back to NFC if USB is selected but unavailable.
    private func makeCCIDTransport(alert: String) async throws -> ManagedTransport {
        if transportMode == .usb, CCIDTransport.isAvailable {
            let t = CCIDTransport()
            try await t.connect()
            return t
        }
        let t = NFCTransport()
        t.alertMessage = alert
        try await t.connect()
        return t
    }

    // ---- FIDO2 state ----
    @Published var fidoInfo: Ctap2Client.Info?
    @Published var fidoRetries: Int?
    @Published var passkeys: [Ctap2Client.Passkey] = []
    @Published var fidoMessage: String?
    @Published var fidoError: String?
    @Published var fidoBusy = false

    /// Session-only remembered FIDO PIN — held in memory for convenience so
    /// consecutive operations don't each re-prompt. NEVER persisted to disk.
    /// Cleared on forgetPin() or process death.
    @Published private(set) var rememberedPin: String?
    func rememberPin(_ pin: String) { rememberedPin = pin }
    func forgetPin() { rememberedPin = nil }
    var hasRememberedPin: Bool { rememberedPin != nil }

    // ---- Info-tab applet statuses (read in one tap) ----
    @Published var infoScanned = false
    @Published var infoBusy = false
    @Published var infoError: String?
    @Published var oathPresent: Bool?
    @Published var token2Present: Bool?
    @Published var fidoPresent: Bool?
    @Published var pivStatus: PIVApplet.PIVStatus?
    @Published var pivAbsent = false
    @Published var pgpStatus: OpenPGPApplet.CardStatus?
    @Published var pgpAbsent = false

    /// Read every applet's presence/status, for the Info tab (NFC tap or USB).
    func scanInfo() async {
        guard !infoBusy else { return }   // prevent concurrent reads on one session
        infoBusy = true; infoError = nil
        oathPresent = nil; token2Present = nil; fidoPresent = nil
        pivStatus = nil; pgpStatus = nil; pivAbsent = false; pgpAbsent = false
        // Reading a (potentially different) key invalidates any data shown on the
        // other tabs — clear OTP codes and FIDO2 info/passkeys so nothing stale
        // lingers from a previously-read key.
        clearKeyData()
        do {
            let transport = try await makeCCIDTransport(alert: "Hold your key near the phone to read what it supports.")
            defer { transport.invalidate(message: "Done.") }
            let isUSB = transport is CCIDTransport

            token2Present = await Token2OTPApplet(transport: transport).isPresent()

            do { try await YKOATHApplet(transport: transport).select(); oathPresent = true }
            catch { oathPresent = false }

            // Read the actual OTP codes in this same session, so switching to the
            // OTP tab shows a populated list instead of prompting another scan.
            if token2Present == true {
                detectedKind = .token2
                try? await readTokens(from: Token2OTPApplet(transport: transport))
            } else if oathPresent == true {
                detectedKind = .oath
                try? await readOATH(transport: transport)
            }

            // FIDO2 rides the key's CTAPHID interface, which isn't reachable over
            // USB on iOS — only probe it over NFC.
            if isUSB {
                fidoPresent = nil          // unknown over USB
            } else {
                do {
                    let info = try await FIDOApplet(transport: transport).getInfo()
                    fidoPresent = true
                    fidoInfo = info
                } catch { fidoPresent = false }
            }

            let piv = PIVApplet(transport: transport)
            if await piv.isPresent() { pivStatus = try? await piv.status() } else { pivAbsent = true }

            let pgp = OpenPGPApplet(transport: transport)
            if await pgp.isPresent() { pgpStatus = try? await pgp.status() } else { pgpAbsent = true }

            infoScanned = true
        } catch let e as KeyError {
            if case .userCancelled = e {} else { infoError = e.errorDescription }
        } catch {
            infoError = error.localizedDescription
        }
        infoBusy = false
    }

    /// Reset per-key data shown across tabs (OTP codes, FIDO2 info, passkeys).
    /// Called when a new key read is initiated so stale data doesn't linger.
    func clearKeyData() {
        credentials = []
        detectedKind = .unknown
        statusMessage = "Ready. Tap a key to read its OTP codes."
        fidoInfo = nil
        fidoRetries = nil
        passkeys = []
        fidoMessage = nil
        fidoError = nil
    }

    struct LiveCode: Identifiable {
        let id: String
        let issuer: String?
        let account: String
        var code: String
        var secondsRemaining: Int
        var touchRequired: Bool = false
    }

    init() {}

    /// Read OATH credentials and compute their current codes over one NFC tap.
    func scanOATH() async {
        guard !isScanning else { return }   // prevent concurrent reads on one session
        isScanning = true
        errorMessage = nil
        // Clear any previously-read codes up front: if this scan fails or is
        // cancelled, the user shouldn't be left looking at stale data from a
        // different key and wondering whether it's current.
        credentials = []
        detectedKind = .unknown
        do {
            let transport = try await makeCCIDTransport(alert: "Hold your key near the phone to read OTP codes.")
            defer { transport.invalidate(message: "Done.") }

            // Auto-detect which applet the key uses, matching the original's
            // routing: try Token2 on-device OTP first, fall back to YKOATH.
            let token2 = Token2OTPApplet(transport: transport)
            if await token2.isPresent() {
                detectedKind = .token2
                try await readTokens(from: token2)
            } else {
                detectedKind = .oath
                try await readOATH(transport: transport)
            }
        } catch let e as KeyError {
            if case .userCancelled = e { /* silent */ }
            else { errorMessage = e.errorDescription }
        } catch {
            errorMessage = error.localizedDescription
        }
        isScanning = false
    }

    /// Read entries from a Token2 on-device OTP applet.
    private func readTokens(from applet: Token2OTPApplet) async throws {
        let now = Int64(Date().timeIntervalSince1970)
        let entries = try await applet.enumerate(timestampSeconds: now)
        var live: [LiveCode] = []
        for e in entries {
            let remaining = e.isTotp ? OATHCore.secondsRemaining(time: Double(now), step: Double(e.timestep)) : 0
            let display: String
            if let code = e.otpCode { display = code }
            else if e.buttonRequired { display = "touch" }
            else if e.isTotp { display = "—" }
            else { display = "— HOTP —" }
            live.append(LiveCode(id: "\(e.appName):\(e.accountName)",
                                 issuer: e.appName.isEmpty ? nil : e.appName,
                                 account: e.accountName,
                                 code: display,
                                 secondsRemaining: remaining,
                                 touchRequired: e.buttonRequired))
        }
        credentials = live
        statusMessage = live.isEmpty ? "No OTP entries on this Token2 key." :
                                       "Read \(live.count) Token2 entry(ies)."
    }

    /// Fetch the code for a single touch-required Token2 entry. READ_ONE makes the
    /// key wait for its physical button, so the user holds the key (NFC) or keeps it
    /// plugged (USB) and touches the button to reveal it.
    func revealTouchCode(id: String) async {
        guard !isScanning else { return }
        isScanning = true; errorMessage = nil
        let (app, acct) = splitId(id)
        do {
            let transport = try await makeCCIDTransport(alert: "Hold the key to the phone and touch its button to reveal the code.")
            defer { transport.invalidate(message: "Revealed."); touchPrompt = nil }
            let token2 = Token2OTPApplet(transport: transport)
            guard await token2.isPresent() else { throw KeyError.appletNotPresent("Token2") }
            // The READ_ONE below blocks until the key's button is pressed. Over USB
            // there's no system NFC sheet, so tell the user in-app to confirm on the
            // key (it will blink until touched).
            touchPrompt = "Touch the blinking button on your key."
            let now = Int64(Date().timeIntervalSince1970)
            let entry = try await token2.readEntry(timestampSeconds: now, app: app, acct: acct)
            touchPrompt = nil
            if let code = entry.otpCode, let idx = credentials.firstIndex(where: { $0.id == id }) {
                credentials[idx].code = code
                credentials[idx].touchRequired = false
                credentials[idx].secondsRemaining = entry.isTotp
                    ? OATHCore.secondsRemaining(time: Double(now), step: Double(entry.timestep)) : 0
                statusMessage = "Revealed code for \(acct)."
            }
        } catch let e as KeyError {
            if case .userCancelled = e {} else { errorMessage = e.errorDescription }
        } catch {
            errorMessage = error.localizedDescription
        }
        isScanning = false
    }

    /// Read credentials from a YKOATH applet.
    private func readOATH(transport: KeyTransport) async throws {
        let applet = YKOATHApplet(transport: transport)
        try await applet.select()
        let creds = try await applet.list()
        var live: [LiveCode] = []
        for cred in creds {
            if cred.kind == .totp {
                let code = try await applet.calculate(cred)
                live.append(LiveCode(id: cred.id, issuer: cred.issuer, account: cred.account,
                                     code: code.value, secondsRemaining: code.secondsRemaining))
            } else {
                live.append(LiveCode(id: cred.id, issuer: cred.issuer, account: cred.account,
                                     code: "— HOTP —", secondsRemaining: 0))
            }
        }
        credentials = live
        statusMessage = live.isEmpty ? "No OATH credentials on this key." :
                                       "Read \(live.count) credential(s)."
    }

    /// Add an OTP entry from the full manual form, routed to Token2 or YKOATH.
    func addEntry(_ fields: OTPEntryFields) async {
        isScanning = true; errorMessage = nil
        do {
            let transport = try await makeCCIDTransport(alert: "Hold your key near the phone to add this credential.")
            defer { transport.invalidate(message: "Added.") }
            let token2 = Token2OTPApplet(transport: transport)
            if await token2.isPresent() {
                detectedKind = .token2
                guard let entry = fields.buildToken2Entry() else {
                    throw KeyError.parsing("Need an account and a valid Base32 secret.")
                }
                try await token2.writeEntry(entry)
                statusMessage = "Added \(entry.appName.isEmpty ? entry.accountName : entry.appName)."
            } else {
                detectedKind = .oath
                guard let uri = fields.buildOtpauthUri(), let parsed = OTPAuthURI(uri) else {
                    throw KeyError.parsing("Need an account and a valid Base32 secret.")
                }
                let applet = YKOATHApplet(transport: transport)
                try await applet.select()
                try await applet.put(parsed, requireTouch: fields.requireTouch)
                statusMessage = "Added \(parsed.label)."
            }
        } catch let e as KeyError {
            if case .userCancelled = e {} else { errorMessage = friendlyPutError(e) }
        } catch {
            errorMessage = error.localizedDescription
        }
        isScanning = false
    }

    /// Add a credential from a scanned/pasted otpauth URI over one NFC tap.
    /// Routes to Token2 or YKOATH depending on which applet the key exposes.
    func addCredential(uri: String, requireTouch: Bool = false) async {
        #if canImport(CoreNFC)
        guard let parsed = OTPAuthURI(uri) else {
            errorMessage = "That isn't a valid otpauth:// URI."
            return
        }
        isScanning = true; errorMessage = nil
        let transport = NFCTransport()
        transport.alertMessage = "Hold your key near the phone to add this credential."
        do {
            try await transport.connect()
            let token2 = Token2OTPApplet(transport: transport)
            if await token2.isPresent() {
                detectedKind = .token2
                let entry = Token2Codec.Entry(
                    type: parsed.kind == .hotp ? Token2Codec.TYPE_HOTP : Token2Codec.TYPE_TOTP,
                    algorithm: parsed.algorithm == .sha256 ? Token2Codec.ALG_SHA256 : Token2Codec.ALG_SHA1,
                    timestep: parsed.period,
                    codeLength: parsed.digits,
                    buttonRequired: requireTouch,
                    appName: parsed.issuerForToken2,
                    accountName: parsed.accountForToken2,
                    seed: parsed.secret)
                try await token2.writeEntry(entry)
            } else {
                detectedKind = .oath
                let applet = YKOATHApplet(transport: transport)
                try await applet.select()
                try await applet.put(parsed, requireTouch: requireTouch)
            }
            statusMessage = "Added \(parsed.label)."
            transport.invalidate(message: "Added.")
        } catch let e as KeyError {
            if case .userCancelled = e {} else { errorMessage = friendlyPutError(e) }
            transport.invalidate()
        } catch {
            errorMessage = error.localizedDescription
            transport.invalidate()
        }
        isScanning = false
        #endif
    }

    /// Delete a credential (NFC tap or USB), routed to Token2 or YKOATH.
    /// For Token2, `id` is "app:account"; for OATH it's the YKOATH name.
    func deleteCredential(id: String) async {
        isScanning = true; errorMessage = nil
        do {
            let transport = try await makeCCIDTransport(alert: "Hold your key near the phone to delete \(id).")
            defer { transport.invalidate(message: "Deleted.") }
            let token2 = Token2OTPApplet(transport: transport)
            if await token2.isPresent() {
                detectedKind = .token2
                let (app, acct) = splitId(id)
                try await token2.deleteEntry(app: app, acct: acct)
            } else {
                detectedKind = .oath
                let applet = YKOATHApplet(transport: transport)
                try await applet.select()
                let cred = OATHCredential(name: id, kind: .totp, algorithm: .sha1, digits: 6)
                try await applet.delete(cred)
            }
            credentials.removeAll { $0.id == id }
            statusMessage = "Deleted \(id)."
        } catch let e as KeyError {
            if case .userCancelled = e {} else { errorMessage = e.errorDescription }
        } catch {
            errorMessage = error.localizedDescription
        }
        isScanning = false
    }

    /// Split an "app:account" id back into its parts (account may itself be empty).
    private func splitId(_ id: String) -> (String, String) {
        if let r = id.range(of: ":") {
            return (String(id[..<r.lowerBound]), String(id[r.upperBound...]))
        }
        return ("", id)
    }

    /// Map YKOATH PUT status words to actionable messages.
    private func friendlyPutError(_ e: KeyError) -> String? {
        if case .unexpectedStatus(let sw) = e {
            switch sw {
            case 0x6A84: return "The key is full — no space for another credential."
            case 0x6982: return "This key requires a password (VALIDATE), which isn't supported yet."
            case 0x6A80: return "The key rejected the credential format (wrong syntax)."
            default: break
            }
        }
        return e.errorDescription
    }

    // MARK: - FIDO2 operations

    /// Run a FIDO operation over one NFC tap. `op` receives a connected applet.
    private func runFido(_ alert: String, _ op: @escaping @MainActor (FIDOApplet) async throws -> Void) async {
        #if canImport(CoreNFC)
        fidoBusy = true; fidoError = nil; fidoMessage = nil
        let transport = NFCTransport()
        transport.alertMessage = alert
        do {
            try await transport.connect()
            let applet = FIDOApplet(transport: transport)
            try await op(applet)
            transport.invalidate(message: "Done.")
        } catch let e as CtapError {
            fidoError = e.localizedDescription
            transport.invalidate()
        } catch let e as KeyError {
            if case .userCancelled = e {} else { fidoError = e.errorDescription }
            transport.invalidate()
        } catch {
            fidoError = error.localizedDescription
            transport.invalidate()
        }
        fidoBusy = false
        #else
        fidoError = "NFC requires a physical iOS device."
        #endif
    }

    func fidoReadInfo() async {
        // Clear prior device info/passkeys up front so a failed or cancelled read
        // doesn't leave stale data from another key on screen.
        fidoInfo = nil
        fidoRetries = nil
        passkeys = []
        await runFido("Hold your key near the phone to read FIDO2 info.") { applet in
            let info = try await applet.getInfo()
            self.fidoInfo = info
            if info.clientPinSet {
                let r = try? await applet.getPinRetries()
                self.fidoRetries = r
            } else {
                self.fidoRetries = nil
            }
        }
    }

    func fidoSetPin(_ newPin: String) async {
        await runFido("Hold your key near the phone to set its PIN.") { applet in
            try await applet.setPin(newPin)
            self.fidoMessage = "PIN set."
        }
    }

    func fidoChangePin(old: String, new: String) async {
        await runFido("Hold your key near the phone to change its PIN.") { applet in
            try await applet.changePin(old: old, new: new)
            self.fidoMessage = "PIN changed."
        }
    }

    func fidoToggleAlwaysUv(pin: String) async {
        await runFido("Hold your key near the phone to toggle alwaysUV.") { applet in
            try await applet.toggleAlwaysUv(pin: pin)
            let info = try await applet.getInfo()
                self.fidoInfo = info
                self.fidoMessage = "alwaysUV is now \(info.alwaysUv ? "on" : "off")."
        }
    }

    func fidoListPasskeys(pin: String) async {
        passkeys = []     // clear before re-reading; failed list shouldn't show stale entries
        await runFido("Hold your key near the phone to list passkeys.") { applet in
            let list = try await applet.listPasskeys(pin: pin)
                self.passkeys = list
                self.fidoMessage = list.isEmpty ? "No passkeys on this key." : "\(list.count) passkey(s)."
        }
    }

    func fidoDeletePasskey(pin: String, credentialId: Data) async {
        await runFido("Hold your key near the phone to delete the passkey.") { applet in
            try await applet.deletePasskey(pin: pin, credentialId: credentialId)
                self.passkeys.removeAll { $0.credentialId == credentialId }
                self.fidoMessage = "Passkey deleted."
        }
    }
}
