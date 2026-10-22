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

    // ---- Token2 OTP PIN (privacy protection, R3.4+) ----
    /// The current Token2 key is PIN-protected (learned from a 6982 on read).
    @Published var otpPinProtected = false
    /// A verified PIN is currently held for reads/writes this scan.
    @Published var otpUnlocked = false
    /// When non-nil, the OTP tab shows a PIN entry sheet for this purpose.
    @Published var otpPinPrompt: OtpPinPrompt?
    /// This key can unlock OTP by fingerprint AND we're on USB (iOS gates the
    /// fingerprint path to USB/CCID only — an NFC session can't hold the field
    /// while the user touches the sensor and polls the capture). Drives whether
    /// the unlock UI offers a "Use fingerprint" action.
    @Published var otpFingerprintUnlockAvailable = false
    /// The key has a fingerprint SENSOR and we're on USB, so fingerprint
    /// protection can be turned on/off — even if it isn't enabled yet. Drives the
    /// enable/disable menu (distinct from the unlock button, which needs the
    /// feature actually usable now).
    @Published var otpFingerprintManageable = false
    /// Last-known "this key can do fingerprint unlock" signal, cached across the
    /// short NFC/USB sessions. Set whenever a config/flag read proves capability.
    /// The *button* also requires USB (see refreshFingerprintAvailability()).
    private var keyFingerprintCapableCache = false
    /// Last-known "this key has a fingerprint sensor" signal, cached similarly.
    private var keyFingerprintSensorCache = false
    /// Remembered OTP PIN — in memory only, never persisted. Cleared on forget/lock.
    @Published private(set) var rememberedOtpPin: String?
    func forgetOtpPin() {
        rememberedOtpPin = nil
        otpUnlocked = false
        otpFingerprintUnlockAvailable = false
        otpFingerprintManageable = false
        keyFingerprintCapableCache = false
        keyFingerprintSensorCache = false
        credentials = []      // clear shown codes immediately
        statusMessage = "OTP PIN forgotten — unlock to view codes."
    }

    /// What a pending OTP-PIN sheet is for.
    struct OtpPinPrompt: Identifiable {
        let id = UUID()
        enum Kind { case unlock, set, change, remove, enableFingerprint, disableFingerprint }
        let kind: Kind
    }

    /// Connection transport for CCID-interface applets (OATH, Token2, PIV, PGP).
    /// FIDO2 follows it only when a `UsbFidoProvider` accepts the attached key;
    /// otherwise FIDO2 uses NFC.
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
            if self.fidoResetArmed {
                // The re-plug the reset was waiting for: run it now, inside the
                // key's post-power-up window, and don't trigger a tab auto-read.
                Task { await self.fidoRunArmedReset() }
                return
            }
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
                self?.oathLocked = false
                self?.forgetOATHPasswords()
                self?.pivStatus = nil; self?.pgpStatus = nil
                self?.pivAbsent = false; self?.pgpAbsent = false
                if self?.fidoResetArmed == true {
                    self?.fidoMessage = "Key removed. Plug it back in to run the reset."
                }
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
    /// True when the last FIDO2 operation ran over USB (vendor channel).
    @Published var fidoOverUSB = false
    /// The channel used last can set a separate alphanumeric PIN minimum.
    @Published var fidoSupportsAlphaMinPin = false
    /// Enrolled fingerprints, as last listed.
    @Published var fingerprints: [Ctap2Client.Fingerprint] = []
    /// Live state of a fingerprint enrollment, for the progress sheet.
    struct EnrollProgress: Equatable {
        var samplesDone = 0
        var remaining: Int?
        var lastStatus: String?
        var finished = false
    }
    @Published var enrollProgress: EnrollProgress?
    private var enrollCancelRequested = false
    /// A USB reset is waiting for the key to be unplugged and plugged back in.
    @Published var fidoResetArmed = false
    private var fidoResetArmedAt: Date?

    /// Session-only remembered FIDO PIN — held in memory for convenience so
    /// consecutive operations don't each re-prompt. NEVER persisted to disk.
    /// Cleared on forgetPin() or process death.
    @Published private(set) var rememberedPin: String?
    func rememberPin(_ pin: String) { rememberedPin = pin }
    func forgetPin() { rememberedPin = nil }
    var hasRememberedPin: Bool { rememberedPin != nil }

    // ---- OATH password (YKOATH VALIDATE) ----

    /// An operation stopped because the OATH applet is locked. The UI presents a
    /// password field; submitting it derives the access key and re-runs `retry`.
    struct OATHPasswordRequest: Identifiable {
        let id = UUID()
        let deviceIdHex: String
        /// True when a password was tried and the key rejected it.
        let wrongPassword: Bool
        let retry: @MainActor () async -> Void
    }
    @Published var oathPasswordRequest: OATHPasswordRequest?

    /// Session-only derived access keys, by device id. Like `rememberedPin`,
    /// held in memory so consecutive taps don't re-prompt, and NEVER persisted.
    /// Storing the derived key rather than the password keeps the plaintext out
    /// of memory once the derivation is done.
    private var oathAccessKeys: [String: Data] = [:]
    func forgetOATHPasswords() { oathAccessKeys.removeAll() }

    /// Derive and cache the key for the pending request, then resume it.
    func submitOATHPassword(_ password: String) {
        guard let request = oathPasswordRequest else { return }
        oathPasswordRequest = nil
        do {
            oathAccessKeys[request.deviceIdHex] = try OATHPassword.deriveAccessKey(
                password: password,
                deviceId: OATHPassword.data(fromHex: request.deviceIdHex))
        } catch {
            errorMessage = (error as? KeyError)?.errorDescription ?? error.localizedDescription
            return
        }
        Task { await request.retry() }
    }

    func cancelOATHPassword() {
        oathPasswordRequest = nil
        statusMessage = "OATH is locked — password not entered."
    }

    /// Raise a password prompt if `error` is an OATH lock. Returns true when it
    /// handled the error, so callers skip their normal error reporting.
    private func requestOATHPassword(for error: Error,
                                     retry: @escaping @MainActor () async -> Void) -> Bool {
        guard let e = error as? KeyError else { return false }
        switch e {
        case .oathPasswordRequired(let deviceId):
            oathPasswordRequest = OATHPasswordRequest(
                deviceIdHex: OATHPassword.hex(deviceId), wrongPassword: false, retry: retry)
            return true
        case .oathPasswordIncorrect(let deviceId):
            // A cached key the applet rejects must never be retried silently.
            oathAccessKeys.removeValue(forKey: OATHPassword.hex(deviceId))
            oathPasswordRequest = OATHPasswordRequest(
                deviceIdHex: OATHPassword.hex(deviceId), wrongPassword: true, retry: retry)
            return true
        default:
            return false
        }
    }

    /// SELECT the OATH applet and unlock it when a password is cached. Throws
    /// `.oathPasswordRequired` / `.oathPasswordIncorrect` when it stays locked.
    private func openOATH(transport: KeyTransport) async throws -> YKOATHApplet {
        let applet = YKOATHApplet(transport: transport)
        let info = try await applet.select()
        guard info.isPasswordProtected else { return applet }
        let deviceIdHex = OATHPassword.hex(info.deviceId)
        guard let accessKey = oathAccessKeys[deviceIdHex] else {
            throw KeyError.oathPasswordRequired(deviceId: info.deviceId)
        }
        do {
            try await applet.validate(accessKey: accessKey)
        } catch let e as KeyError {
            if case .oathPasswordIncorrect = e { oathAccessKeys.removeValue(forKey: deviceIdHex) }
            throw e
        }
        return applet
    }

    // ---- Info-tab applet statuses (read in one tap) ----
    @Published var infoScanned = false
    @Published var infoBusy = false
    @Published var infoError: String?
    @Published var oathPresent: Bool?
    /// OATH is present but password protected and not unlocked in this session.
    @Published var oathLocked = false
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
        oathPresent = nil; token2Present = nil; fidoPresent = nil; oathLocked = false
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

            // SELECT answers on a password-protected applet too, so record the
            // lock separately instead of reporting the applet as missing when a
            // later LIST comes back 6982.
            do {
                let info = try await YKOATHApplet(transport: transport).select()
                oathPresent = true
                oathLocked = info.isPasswordProtected
                    && oathAccessKeys[OATHPassword.hex(info.deviceId)] == nil
            } catch {
                oathPresent = false
            }

            // Read the actual OTP codes in this same session, so switching to the
            // OTP tab shows a populated list instead of prompting another scan.
            if token2Present == true {
                detectedKind = .token2
                try? await readTokens(from: Token2OTPApplet(transport: transport))
            } else if oathPresent == true, !oathLocked {
                detectedKind = .oath
                try? await readOATH(transport: transport)
            }

            // Over USB the standard FIDO2 binding isn't reachable (CTAPHID). Probe
            // through a registered USB provider if there is one; otherwise unknown.
            if isUSB {
                if let channel = await usbFidoChannel(transport) {
                    do {
                        let info = try await FIDOApplet(channel: channel).getInfo()
                        fidoPresent = true
                        fidoInfo = info
                        fidoOverUSB = true
                        fidoSupportsAlphaMinPin = channel.supportsAlphanumericMinPin
                    } catch { fidoPresent = nil }
                } else {
                    fidoPresent = nil      // unknown over USB
                }
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
        fingerprints = []
        fidoOverUSB = false
        fidoSupportsAlphaMinPin = false
        token2Channels = nil
        channelsMessage = nil
        channelsError = nil
        resetFingerprintAvailability()
    }

    private func resetFingerprintAvailability() {
        keyFingerprintCapableCache = false
        keyFingerprintSensorCache = false
        otpFingerprintUnlockAvailable = false
        otpFingerprintManageable = false
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
        resetFingerprintAvailability()   // decided afresh for whichever key this is
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
            else if case .otpPinNotVerified = e {
                // Protected key, no/again-wrong PIN: show the unlock sheet.
                otpPinProtected = true; otpUnlocked = false
                otpFingerprintUnlockAvailable = (transportMode == .usb) && keyFingerprintCapableCache
                otpFingerprintManageable = (transportMode == .usb) && keyFingerprintSensorCache
                statusMessage = "These codes are PIN-protected. Enter your OTP PIN to unlock."
                otpPinPrompt = OtpPinPrompt(kind: .unlock)
            }
            else if case .otpPinBlocked = e {
                otpPinProtected = true
                errorMessage = e.errorDescription
            }
            else if requestOATHPassword(for: e, retry: { [weak self] in
                guard let self else { return }
                await self.scanOATH()
            }) {}
            else { errorMessage = e.errorDescription }
        } catch {
            errorMessage = error.localizedDescription
        }
        isScanning = false
    }

    /// Read entries from a Token2 on-device OTP applet.
    private func readTokens(from applet: Token2OTPApplet) async throws {
        let now = Int64(Date().timeIntervalSince1970)

        // Determine whether this key even has an OTP PIN before touching any PIN
        // path. On firmware without the feature (or a key with no PIN set),
        // pinStatus reports not-set (or throws unsupported), and we read normally.
        var isProtected = false
        do {
            isProtected = try await applet.pinStatus().isSet
        } catch KeyError.otpPinNotVerified {
            isProtected = true             // firmware answers the flag read only when locked
        } catch {
            // Any other outcome (otpPinUnsupported, unexpectedStatus, older
            // firmware that doesn't know the flag command) means this key has no
            // usable OTP PIN — read it normally without any PIN path.
            isProtected = false
        }
        otpPinProtected = isProtected

        if isProtected {
            // Learn whether fingerprint unlock is offerable: the key must support
            // it (or already have it enabled) AND we must be on USB (iOS gates the
            // fingerprint poll to CCID). Best effort — failure just hides the option.
            await refreshFingerprintAvailability(applet)

            guard let pin = rememberedOtpPin else {
                // Protected but we hold no PIN — prompt to unlock, read nothing yet.
                otpUnlocked = false
                credentials = []
                statusMessage = otpFingerprintUnlockAvailable
                    ? "These codes are protected. Touch the fingerprint sensor, or enter your OTP PIN."
                    : "These codes are PIN-protected. Enter your OTP PIN to unlock."
                otpPinPrompt = OtpPinPrompt(kind: .unlock)
                return
            }
            do {
                try await applet.verifyOtpPin(Data(pin.utf8))
                otpUnlocked = true
            } catch KeyError.otpPinNotVerified {
                rememberedOtpPin = nil; otpUnlocked = false
                credentials = []
                statusMessage = "Wrong OTP PIN. Enter it again to unlock."
                otpPinPrompt = OtpPinPrompt(kind: .unlock)
                return
            }
        } else {
            otpUnlocked = false
        }

        let entries = try await applet.enumerate(timestampSeconds: now)
        credentials = liveCodes(from: entries, now: now)
        statusMessage = credentials.isEmpty ? "No OTP entries on this Token2 key." :
                                              "Read \(credentials.count) Token2 entry(ies)."
    }

    // MARK: - OTP PIN operations (each is one NFC session)

    /// Run a block against a freshly-connected Token2 applet in one session.
    private func withToken2<T>(alert: String, _ body: (Token2OTPApplet) async throws -> T) async throws -> T {
        let transport = try await makeCCIDTransport(alert: alert)
        defer { transport.invalidate(message: "Done.") }
        let token2 = Token2OTPApplet(transport: transport)
        guard await token2.isPresent() else { throw KeyError.appletNotPresent("Token2") }
        return try await body(token2)
    }

    /// Read PIN status (for the set/change/remove menu).
    func otpReadPinStatus() async -> Token2OTPApplet.PinFlag? {
        do { return try await withToken2(alert: "Hold your key near the phone.") { try await $0.pinStatus() } }
        catch { await MainActor.run { self.mapOtpPinError(error) }; return nil }
    }

    /// Unlock: verify the PIN, then read codes — in one session.
    func otpUnlock(pin: String, remember: Bool) async {
        isScanning = true; errorMessage = nil
        do {
            try await withToken2(alert: "Hold your key near the phone to unlock codes.") { applet in
                try await applet.verifyOtpPin(Data(pin.utf8))
                self.otpPinProtected = true; self.otpUnlocked = true
                let now = Int64(Date().timeIntervalSince1970)
                let entries = try await applet.enumerate(timestampSeconds: now)
                self.credentials = self.liveCodes(from: entries, now: now)
                self.statusMessage = "Read \(self.credentials.count) Token2 entry(ies)."
            }
            // Keep the PIN only if the user asked to remember it (in memory only).
            rememberedOtpPin = remember ? pin : nil
        } catch KeyError.otpPinNotVerified {
            rememberedOtpPin = nil; otpUnlocked = false
            let left = (try? await otpReadRetries()) ?? nil
            errorMessage = left.map { "Wrong OTP PIN — \($0) of 100 attempts left." } ?? "Wrong OTP PIN."
            otpFingerprintUnlockAvailable = (transportMode == .usb) && keyFingerprintCapableCache
            otpFingerprintManageable = (transportMode == .usb) && keyFingerprintSensorCache
            otpPinPrompt = OtpPinPrompt(kind: .unlock)
        } catch {
            rememberedOtpPin = nil
            mapOtpPinError(error)
        }
        isScanning = false
    }

    private func otpReadRetries() async throws -> Int? {
        try await withToken2(alert: "Hold your key near the phone.") { try await $0.pinStatus().retriesLeft }
    }

    /// Probe capability against a live applet, cache it, and recompute whether the
    /// fingerprint-unlock button should show (capable AND on USB). Call this before
    /// raising an unlock prompt from any path that has an applet in hand.
    /// Decide, for the key in this session, whether it has a fingerprint sensor
    /// (manage) and can unlock OTP by fingerprint (unlock). Recomputed per key —
    /// never carried over from a previously connected one.
    ///
    /// The sensor answer comes from FIDO2 getInfo (`bioEnroll` present) when it's
    /// reachable — that's authoritative. The vendor config byte's fingerprint bit
    /// isn't reliable on every model, so it's only a fallback, and only when the
    /// key actually returned that byte. No sensor ⇒ no fingerprint options, even
    /// if a flag byte claims otherwise.
    private func refreshFingerprintAvailability(_ applet: Token2OTPApplet) async {
        var sensor: Bool?
        // 1. FIDO2 getInfo over USB through the build's provider (same session).
        if let channel = await usbFidoChannel(applet.transport) {
            sensor = (try? await FIDOApplet(channel: channel).getInfo())?.supportsBioEnroll
            try? await applet.select()   // back to the OTP applet before PIN commands
        }
        // 2. FIDO2 info already read over USB from the plugged-in key.
        if sensor == nil, fidoOverUSB, let fi = fidoInfo { sensor = fi.supportsBioEnroll }
        // 3. Vendor config, only if the capability byte came back.
        let config = try? await applet.readConfig()
        if sensor == nil, let c = config, c.hasConfigByte { sensor = c.fingerprintPresent }

        let hasSensor = sensor ?? false
        // (No `await` inside || — autoclosures can't suspend.)
        let fpEnabledNow = hasSensor ? ((try? await applet.pinStatus())?.fpEnable == true) : false
        let configSaysSupported = config?.hasConfigByte == true && config?.otpFingerprintProtectSupported == true
        // A PIN-protected key is R3.4+, where Bio keys support fingerprint unlock.
        let protectSupported = configSaysSupported || fpEnabledNow || otpPinProtected
        keyFingerprintSensorCache = hasSensor
        keyFingerprintCapableCache = hasSensor && protectSupported
        let onUSB = (transportMode == .usb)
        otpFingerprintUnlockAvailable = onUSB && keyFingerprintCapableCache
        otpFingerprintManageable      = onUSB && keyFingerprintSensorCache
    }

    /// Unlock by fingerprint (USB only): the key opens the read window on a touch,
    /// then we enumerate over the same session — no PIN typed.
    func otpUnlockWithFingerprint() async {
        guard transportMode == .usb else {
            errorMessage = "Fingerprint unlock needs the key plugged in over USB."
            return
        }
        isScanning = true; errorMessage = nil
        statusMessage = "Touch the fingerprint sensor on the key…"
        do {
            try await withToken2(alert: "Touch the fingerprint sensor on the key to unlock codes.") { applet in
                try await applet.verifyOtpFingerprint()
                self.otpPinProtected = true; self.otpUnlocked = true
                let now = Int64(Date().timeIntervalSince1970)
                let entries = try await applet.enumerate(timestampSeconds: now)
                self.credentials = self.liveCodes(from: entries, now: now)
                self.statusMessage = "Read \(self.credentials.count) Token2 entry(ies)."
            }
        } catch { mapOtpPinError(error) }
        isScanning = false
    }

    /// Enable/disable fingerprint-protected OTP (§1.20). Rides on VERIFY_OTP_PIN,
    /// so it needs the current PIN. USB only (fingerprint enrolment/verification
    /// path). On enable with no enrolled finger, the applet returns a clear error.
    func otpSetFingerprintProtection(pin: String, enable: Bool) async {
        guard transportMode == .usb else {
            errorMessage = "Changing fingerprint protection needs the key plugged in over USB."
            return
        }
        isScanning = true; errorMessage = nil
        do {
            try await withToken2(alert: "Hold your key to change fingerprint protection.") { applet in
                try await applet.verifyOtpPin(Data(pin.utf8), fpEnable: enable)
                try? await applet.lockOtpPin()   // don't leave the window open
            }
            statusMessage = enable
                ? "Fingerprint protection enabled — a fingerprint can now unlock OTP codes."
                : "Fingerprint protection disabled."
        } catch { mapOtpPinError(error) }
        isScanning = false
    }

    func otpSetPin(_ pin: String) async {
        await runOtpPinChange(alert: "Hold your key near the phone to set the OTP PIN.") {
            try await $0.setOtpPin(Data(pin.utf8))
        } success: { "OTP PIN set." }
    }
    func otpChangePin(current: String, new: String) async {
        await runOtpPinChange(alert: "Hold your key near the phone to change the OTP PIN.") {
            try await $0.changeOtpPin(current: Data(current.utf8), new: Data(new.utf8))
        } success: { "OTP PIN changed." }
    }
    func otpRemovePin(current: String) async {
        await runOtpPinChange(alert: "Hold your key near the phone to remove the OTP PIN.") {
            try await $0.removeOtpPin(current: Data(current.utf8))
        } success: { self.otpPinProtected = false; self.otpUnlocked = false; return "OTP PIN removed." }
    }

    private func runOtpPinChange(alert: String,
                                 _ op: @escaping (Token2OTPApplet) async throws -> Void,
                                 success: @escaping () -> String) async {
        isScanning = true; errorMessage = nil
        do {
            try await withToken2(alert: alert) { try await op($0) }
            statusMessage = success()
        } catch { mapOtpPinError(error) }
        isScanning = false
    }

    /// Lock: forget the PIN and close the device window on the next contact.
    func otpLock() async {
        // Forget the PIN and clear the shown codes immediately. No NFC tap is
        // needed: each scan is its own session, so the device's verify window is
        // already closed once the read that opened it ended. Re-reading a
        // protected key will prompt for the PIN again.
        rememberedOtpPin = nil
        otpUnlocked = false
        credentials = []
        errorMessage = nil
        statusMessage = "OTP codes locked — unlock to view."
    }

    private func liveCodes(from entries: [Token2Codec.Entry], now: Int64) -> [LiveCode] {
        entries.map { e in
            let remaining = e.isTotp ? OATHCore.secondsRemaining(time: Double(now), step: Double(e.timestep)) : 0
            let display: String
            if let code = e.otpCode { display = code }
            else if e.buttonRequired { display = "touch" }
            else if e.isTotp { display = "—" }
            else { display = "— HOTP —" }
            return LiveCode(id: "\(e.appName):\(e.accountName)",
                            issuer: e.appName.isEmpty ? nil : e.appName,
                            account: e.accountName, code: display,
                            secondsRemaining: remaining, touchRequired: e.buttonRequired)
        }
    }

    private func mapOtpPinError(_ error: Error) {
        if let e = error as? KeyError {
            if case .userCancelled = e { return }
            errorMessage = e.errorDescription
        } else {
            errorMessage = error.localizedDescription
        }
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
        let applet = try await openOATH(transport: transport)
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
                // On a protected key we must open the verify window on this same
                // session before the write (which then uses the session-key format).
                var isProtected = false
                do { isProtected = try await token2.pinStatus().isSet }
                catch KeyError.otpPinNotVerified { isProtected = true }
                catch { isProtected = false }

                if isProtected {
                    // Open the verify window on THIS session before the write.
                    // Priority: a remembered PIN (silent), else a fingerprint touch
                    // if the key supports it on USB, else ask the user to unlock.
                    await refreshFingerprintAvailability(token2)
                    if let pin = rememberedOtpPin {
                        try await token2.verifyOtpPin(Data(pin.utf8))
                    } else if otpFingerprintUnlockAvailable {
                        // Fingerprint-only: authorize the write with a touch, in
                        // this same session (matches the read path).
                        statusMessage = "Touch the fingerprint sensor on the key…"
                        try await token2.verifyOtpFingerprint()
                    } else {
                        // No PIN held and no fingerprint path — ask to unlock first.
                        otpPinProtected = true; otpUnlocked = false
                        isScanning = false
                        errorMessage = "This key is PIN-protected. Unlock it first, then add the entry."
                        otpPinPrompt = OtpPinPrompt(kind: .unlock)
                        return
                    }
                }
                try await token2.writeEntry(entry)
                // Refresh in the SAME session: the verify window is still open
                // (PIN/fingerprint just authorized the write), so re-enumerate and
                // show the new entry immediately instead of leaving a stale list.
                let now = Int64(Date().timeIntervalSince1970)
                let entries = try await token2.enumerate(timestampSeconds: now)
                credentials = liveCodes(from: entries, now: now)
                if isProtected { otpPinProtected = true; otpUnlocked = true }
                statusMessage = "Added \(entry.appName.isEmpty ? entry.accountName : entry.appName)."
            } else {
                detectedKind = .oath
                guard let uri = fields.buildOtpauthUri(), let parsed = OTPAuthURI(uri) else {
                    throw KeyError.parsing("Need an account and a valid Base32 secret.")
                }
                try await openOATH(transport: transport).put(parsed, requireTouch: fields.requireTouch)
                // Refresh from the same session so the new credential shows at once.
                try await readOATH(transport: transport)
                statusMessage = "Added \(parsed.label)."
            }
        } catch let e as KeyError {
            if case .userCancelled = e {}
            else if requestOATHPassword(for: e, retry: { [weak self] in
                guard let self else { return }
                await self.addEntry(fields)
            }) {}
            else { errorMessage = friendlyPutError(e) }
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
                let now = Int64(Date().timeIntervalSince1970)
                let entries = try await token2.enumerate(timestampSeconds: now)
                credentials = liveCodes(from: entries, now: now)
            } else {
                detectedKind = .oath
                try await openOATH(transport: transport).put(parsed, requireTouch: requireTouch)
                try await readOATH(transport: transport)
            }
            statusMessage = "Added \(parsed.label)."
            transport.invalidate(message: "Added.")
        } catch let e as KeyError {
            if case .userCancelled = e {}
            else if requestOATHPassword(for: e, retry: { [weak self] in
                guard let self else { return }
                await self.addCredential(uri: uri, requireTouch: requireTouch)
            }) {}
            else { errorMessage = friendlyPutError(e) }
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
                var isProtected = false
                do { isProtected = try await token2.pinStatus().isSet }
                catch KeyError.otpPinNotVerified { isProtected = true }
                catch { isProtected = false }

                if isProtected {
                    await refreshFingerprintAvailability(token2)
                    if let pin = rememberedOtpPin {
                        try await token2.verifyOtpPin(Data(pin.utf8))
                    } else if otpFingerprintUnlockAvailable {
                        statusMessage = "Touch the fingerprint sensor on the key…"
                        try await token2.verifyOtpFingerprint()
                    } else {
                        otpPinProtected = true; otpUnlocked = false
                        isScanning = false
                        errorMessage = "This key is PIN-protected. Unlock it first, then delete."
                        otpPinPrompt = OtpPinPrompt(kind: .unlock)
                        return
                    }
                }
                try await token2.deleteEntry(app: app, acct: acct)
            } else {
                detectedKind = .oath
                let applet = try await openOATH(transport: transport)
                let cred = OATHCredential(name: id, kind: .totp, algorithm: .sha1, digits: 6)
                try await applet.delete(cred)
            }
            credentials.removeAll { $0.id == id }
            statusMessage = "Deleted \(id)."
        } catch let e as KeyError {
            if case .userCancelled = e {}
            else if requestOATHPassword(for: e, retry: { [weak self] in
                guard let self else { return }
                await self.deleteCredential(id: id)
            }) {}
            else { errorMessage = e.errorDescription }
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
            case 0x6982: return "The key's OATH applet is locked — enter its password and try again."
            case 0x6A80: return "The key rejected the credential format (wrong syntax)."
            default: break
            }
        }
        return e.errorDescription
    }

    // MARK: - FIDO2 operations

    /// A FIDO2 channel over an already-connected USB transport, if this build has
    /// a provider and it accepts the attached key.
    private func usbFidoChannel(_ transport: KeyTransport) async -> CtapChannel? {
        guard let provider = UsbFido.provider, let usb = transport as? CCIDTransport else { return nil }
        return await provider.channel(for: usb, slotName: usb.slotName)
    }

    /// Run a FIDO operation over USB when a provider accepts the attached key,
    /// otherwise over one NFC tap. `op` receives a connected applet.
    private func runFido(_ alert: String, _ op: @escaping @MainActor (FIDOApplet) async throws -> Void) async {
        fidoBusy = true; fidoError = nil; fidoMessage = nil
        defer { fidoBusy = false }

        var nfcAlert = alert
        if transportMode == .usb, CCIDTransport.isAvailable, UsbFido.provider != nil {
            let usb = CCIDTransport()
            var channel: CtapChannel?
            do {
                try await usb.connect()
                channel = await usbFidoChannel(usb)
            } catch {
                channel = nil
            }
            if let channel {
                fidoOverUSB = true
                fidoSupportsAlphaMinPin = channel.supportsAlphanumericMinPin
                await runFidoOp(op, FIDOApplet(channel: channel)) { usb.invalidate(message: $0) }
                return
            }
            usb.invalidate(message: nil)
            nfcAlert = "FIDO2 over USB isn't available for this key. " + alert
        }

        #if canImport(CoreNFC)
        let transport = NFCTransport()
        transport.alertMessage = nfcAlert
        do {
            try await transport.connect()
        } catch let e as KeyError {
            if case .userCancelled = e {} else { fidoError = e.errorDescription }
            transport.invalidate()
            return
        } catch {
            fidoError = error.localizedDescription
            transport.invalidate()
            return
        }
        fidoOverUSB = false
        fidoSupportsAlphaMinPin = false
        await runFidoOp(op, FIDOApplet(transport: transport)) { transport.invalidate(message: $0) }
        #else
        fidoError = "NFC requires a physical iOS device."
        #endif
    }

    /// Run `op`, map its errors onto `fidoError`, then close the session.
    private func runFidoOp(_ op: @MainActor (FIDOApplet) async throws -> Void,
                           _ applet: FIDOApplet,
                           close: (String?) -> Void) async {
        do {
            try await op(applet)
            close("Done.")
        } catch let e as CtapError {
            fidoError = friendlyCtap(e)
            close(nil)
        } catch let e as KeyError {
            if case .userCancelled = e {} else { fidoError = e.errorDescription }
            close(nil)
        } catch {
            fidoError = error.localizedDescription
            close(nil)
        }
    }

    private func friendlyCtap(_ e: CtapError) -> String {
        switch e.code {
        case 0x30: return "The key refused the reset. Reset only works within about 10 seconds of plugging the key in or tapping it, and may need a touch."
        case 0x2F: return "Timed out waiting for a touch on the key."
        case 0x37: return "PIN policy violation — the new value doesn't meet the key's PIN rules (a minimum PIN length can only be raised)."
        case 0x3E: return "The key's fingerprint storage is full."
        default: return e.localizedDescription
        }
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

    // MARK: - FIDO2 minimum PIN length

    func fidoSetMinPinLength(pin: String, length: Int, alphanumeric: Bool) async {
        await runFido("Hold your key near the phone to set the minimum PIN length.") { applet in
            try await applet.setMinPinLength(pin: pin, length: length, alphanumeric: alphanumeric)
            let info = try await applet.getInfo()
            self.fidoInfo = info
            self.fidoMessage = alphanumeric
                ? "Minimum length for PINs with letters or symbols is now \(length)."
                : "Minimum PIN length is now \(length)."
        }
    }

    // MARK: - FIDO2 reset

    /// Reset FIDO2. Over NFC the tap itself powers the key up, so the reset runs
    /// immediately. Over USB the key must be re-plugged first: this arms the reset
    /// and the USB monitor runs it as soon as the key is detected again.
    func fidoReset() async {
        let usbProviderUsable = transportMode == .usb && CCIDTransport.isAvailable && UsbFido.provider != nil
        if usbProviderUsable && fidoOverUSB {
            fidoError = nil
            fidoResetArmed = true
            fidoResetArmedAt = Date()
            fidoMessage = "Unplug the key and plug it back in. The reset runs as soon as the key is detected — touch it if it blinks."
            return
        }
        await fidoResetNow(alert: "Hold your key near the phone to reset FIDO2. Touch it if it blinks.")
    }

    func fidoCancelArmedReset() {
        fidoResetArmed = false
        fidoResetArmedAt = nil
        fidoMessage = "Reset cancelled."
    }

    fileprivate func fidoRunArmedReset() async {
        let fresh = fidoResetArmedAt.map { Date().timeIntervalSince($0) < 120 } ?? false
        fidoResetArmed = false
        fidoResetArmedAt = nil
        guard fresh else { fidoMessage = nil; usbCardReady = true; return }
        await fidoResetNow(alert: "Hold your key near the phone to reset FIDO2.")
    }

    private func fidoResetNow(alert: String) async {
        await runFido(alert) { applet in
            try await applet.reset()
            self.passkeys = []
            self.fingerprints = []
            self.forgetPin()
            self.fidoInfo = try? await applet.getInfo()
            self.fidoRetries = nil
            self.fidoMessage = "FIDO2 reset. All passkeys and fingerprints were erased and the PIN was cleared."
        }
    }

    // MARK: - FIDO2 fingerprints

    func fidoListFingerprints(pin: String) async {
        fingerprints = []
        await runFido("Hold your key near the phone to list fingerprints.") { applet in
            let list = try await applet.bioSession(pin: pin).list()
            self.fingerprints = list
            self.fidoMessage = list.isEmpty ? "No fingerprints enrolled." : "\(list.count) fingerprint(s)."
        }
    }

    func fidoRenameFingerprint(pin: String, templateId: Data, name: String) async {
        await runFido("Hold your key near the phone to rename the fingerprint.") { applet in
            let bio = try await applet.bioSession(pin: pin)
            try await bio.rename(templateId: templateId, name: name)
            self.fingerprints = try await bio.list()
            self.fidoMessage = "Fingerprint renamed."
        }
    }

    func fidoRemoveFingerprint(pin: String, templateId: Data) async {
        await runFido("Hold your key near the phone to delete the fingerprint.") { applet in
            let bio = try await applet.bioSession(pin: pin)
            try await bio.remove(templateId: templateId)
            self.fingerprints = try await bio.list()
            self.fidoMessage = "Fingerprint deleted."
        }
    }

    /// Enroll a new fingerprint. Needs a channel that holds the session across
    /// touches (USB); progress is published through `enrollProgress`.
    func fidoEnrollFingerprint(pin: String, name: String) async {
        enrollCancelRequested = false
        enrollProgress = EnrollProgress()
        await runFido("Hold your key near the phone to enroll a fingerprint.") { applet in
            guard applet.holdsSession else {
                throw KeyError.unsupportedOnPlatform("Fingerprint enrollment needs the key plugged in over USB-C.")
            }
            let bio = try await applet.bioSession(pin: pin)
            var s = try await bio.enrollBegin()
            self.recordSample(s)
            while !s.complete {
                if self.enrollCancelRequested {
                    await bio.cancelEnrollment()
                    self.enrollProgress = nil
                    self.fidoMessage = "Enrollment cancelled."
                    return
                }
                if s.remaining == 0 && s.lastStatus != 0 { break }
                s = try await bio.captureNext(templateId: s.templateId)
                self.recordSample(s)
            }
            let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { try? await bio.rename(templateId: s.templateId, name: trimmed) }
            self.fingerprints = (try? await bio.list()) ?? self.fingerprints
            self.fidoInfo = (try? await applet.getInfo()) ?? self.fidoInfo
            self.enrollProgress?.finished = true
            self.fidoMessage = "Fingerprint enrolled."
        }
        if fidoError != nil { enrollProgress = nil }
    }

    func fidoCancelEnrollment() { enrollCancelRequested = true }

    private func recordSample(_ s: Ctap2Client.EnrollSample) {
        var p = enrollProgress ?? EnrollProgress()
        if s.lastStatus == 0 { p.samplesDone += 1 }
        p.remaining = s.remaining
        p.lastStatus = Ctap2Client.sampleStatusText(s.lastStatus)
        enrollProgress = p
    }

    // MARK: - Token2 USB channels (FIDO / HID-HOTP / CCID)

    @Published var token2Channels: Token2OTPApplet.Channels?
    @Published var channelsBusy = false
    @Published var channelsMessage: String?
    @Published var channelsError: String?

    /// Read which USB channels are on (READ_CONFIG byte 0). Works over NFC or USB.
    func readChannels() async {
        guard !channelsBusy else { return }
        channelsBusy = true; channelsError = nil; channelsMessage = nil
        defer { channelsBusy = false }
        do {
            let info = try await withToken2(alert: "Hold your key near the phone to read its USB channels.") {
                try await $0.readConfig()
            }
            guard let c = info.channels else {
                token2Channels = nil
                channelsError = "The key didn't report its channel settings."
                return
            }
            token2Channels = c
        } catch let e as KeyError {
            if case .userCancelled = e {} else { channelsError = e.errorDescription }
        } catch {
            channelsError = error.localizedDescription
        }
    }

    /// Apply channel settings. The key restarts to apply them; over USB that cuts
    /// the connection, so a lost response after the command was sent is expected.
    func applyChannels(_ c: Token2OTPApplet.Channels) async {
        guard !channelsBusy else { return }
        channelsBusy = true; channelsError = nil; channelsMessage = nil
        defer { channelsBusy = false }
        let overUSB = transportMode == .usb && CCIDTransport.isAvailable
        var sent = false
        do {
            try await withToken2(alert: "Hold your key near the phone to change its USB channels.") { applet in
                // A PIN-protected key may want the OTP verify window open first.
                if let pin = rememberedOtpPin { try? await applet.verifyOtpPin(Data(pin.utf8)) }
                sent = true
                try await applet.setChannels(c)
            }
            token2Channels = c
            channelsMessage = overUSB
                ? "Saved. The key restarts to apply it — it will reconnect in a moment."
                : "Saved. The change takes effect the next time the key is plugged in."
        } catch KeyError.otpPinNotVerified {
            channelsError = "This key's OTP PIN is set. Unlock the OTP tab with \"Remember PIN\" turned on, then try again."
        } catch KeyError.unexpectedStatus(let sw) {
            channelsError = String(format: "The key refused the change (0x%04X).", sw)
        } catch let e as KeyError where sent && overUSB && !isUserCancel(e) {
            // The key rebooted before answering — expected when it applies the change.
            token2Channels = c
            channelsMessage = "Sent. The key restarted to apply it; re-read to confirm once it reconnects."
        } catch let e as KeyError {
            if !isUserCancel(e) { channelsError = e.errorDescription }
        } catch where sent && overUSB {
            token2Channels = c
            channelsMessage = "Sent. The key restarted to apply it; re-read to confirm once it reconnects."
        } catch {
            channelsError = error.localizedDescription
        }
    }

    private func isUserCancel(_ e: KeyError) -> Bool {
        if case .userCancelled = e { return true }
        return false
    }
}
