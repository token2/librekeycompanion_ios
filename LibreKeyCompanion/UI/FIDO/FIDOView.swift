import SwiftUI

/// FIDO2 management tab: authenticator info, PIN set/change, minimum PIN length,
/// alwaysUV toggle, passkeys, fingerprints and reset. Each action runs over one
/// NFC tap, or over USB-C when this build can reach the plugged-in key's FIDO2
/// applet there. PIN-gated actions prompt for the PIN. Mirrors the Android
/// FIDO2 screen; fingerprint enrollment needs the USB connection.
struct FIDOView: View {
    @EnvironmentObject var session: KeySession
    @EnvironmentObject var mds: MDSRepository
    @State private var sheet: ActiveSheet?
    @State private var showPasskeyManager = false
    @State private var showFingerprintManager = false
    @State private var confirmReset = false

    enum ActiveSheet: Identifiable {
        case setPin, changePin, alwaysUv, listPasskeys, minPin, minPinAlpha, listFingerprints
        var id: Int { hashValue }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button {
                        Task { await session.fidoReadInfo() }
                    } label: {
                        Label(session.fidoBusy ? "Reading…" : "Read Device",
                              systemImage: "wave.3.right")
                    }
                    .disabled(session.fidoBusy)
                }

                if let msg = session.fidoMessage {
                    Section { Text(msg).foregroundStyle(.green).font(.callout) }
                }
                if let err = session.fidoError {
                    Section { Text(err).foregroundStyle(.orange).font(.callout) }
                }
                if session.fidoResetArmed {
                    Section {
                        Label("Waiting for the key to be plugged back in…", systemImage: "cable.connector")
                            .font(.callout)
                        Button("Cancel reset", role: .cancel) { session.fidoCancelArmedReset() }
                    }
                }

                if let info = session.fidoInfo {
                    if let a = info.aaguidHex, let entry = mds.lookup(aaguid: a) {
                        Section {
                            DeviceHeaderCard(entry: entry)
                        }
                    }
                    Section("Authenticator") {
                        row("Connection", session.fidoOverUSB ? "USB-C" : "NFC")
                        row("Versions", info.versions.joined(separator: ", "))
                        if let a = info.aaguidHex { row("AAGUID", a) }
                        row("PIN protocols", info.pinProtocols.map(String.init).joined(separator: ", "))
                        row("PIN set", info.clientPinSet ? "Yes" : "No")
                        row("alwaysUV", info.alwaysUv ? "On" : "Off")
                        row("Credential mgmt", info.supportsCredMgmt ? "Supported" : "—")
                        if let r = session.fidoRetries { row("PIN retries left", "\(r)") }
                        if let m = info.minPinLength { row("Min PIN length", "\(m)") }
                    }

                    Section("PIN") {
                        if info.clientPinSet {
                            Button("Change PIN") { sheet = .changePin }
                        } else {
                            Button("Set PIN") { sheet = .setPin }
                        }
                        if info.clientPinSet && info.supportsSetMinPinLength {
                            Button("Raise minimum PIN length") { sheet = .minPin }
                        }
                        if info.clientPinSet && info.supportsConfig && session.fidoSupportsAlphaMinPin {
                            Button("Minimum length for PINs with letters") { sheet = .minPinAlpha }
                        }
                        if session.hasRememberedPin {
                            Button("Forget remembered PIN", role: .destructive) {
                                session.forgetPin()
                            }
                        }
                    }

                    if info.supportsConfig {
                        Section("Config") {
                            Button(info.alwaysUv ? "Turn alwaysUV off" : "Turn alwaysUV on") {
                                sheet = .alwaysUv
                            }
                        }
                    }

                    if info.supportsCredMgmt {
                        Section("Passkeys") {
                            Button("Manage passkeys") { sheet = .listPasskeys }
                        }
                    }

                    if info.supportsBioEnroll {
                        Section {
                            Button("Manage fingerprints") {
                                if info.clientPinSet { sheet = .listFingerprints }
                                else { session.fidoError = "Set a PIN first — fingerprints are managed with the key's PIN." }
                            }
                        } header: {
                            Text("Fingerprints")
                        } footer: {
                            if !session.fidoOverUSB {
                                Text("Enrolling a new fingerprint needs the key plugged in over USB-C.")
                            }
                        }
                    }

                    Section {
                        Button("Reset FIDO2…", role: .destructive) { confirmReset = true }
                            .disabled(session.fidoResetArmed)
                    } header: {
                        Text("Danger zone")
                    } footer: {
                        Text(session.fidoOverUSB
                             ? "Erases every passkey and fingerprint and clears the PIN. You'll be asked to unplug and re-plug the key."
                             : "Erases every passkey and fingerprint and clears the PIN. Tap the key right after confirming.")
                    }
                }
            }
            .navigationTitle("FIDO2")
            .sheet(item: $sheet) { which in
                switch which {
                case .setPin:
                    PinSheet(title: "Set PIN", needsOld: false) { _, new, remember in
                        if remember { session.rememberPin(new) }
                        Task { await session.fidoSetPin(new) }
                    }
                case .changePin:
                    PinSheet(title: "Change PIN", needsOld: true) { old, new, remember in
                        if remember { session.rememberPin(new) }
                        Task { await session.fidoChangePin(old: old, new: new) }
                    }
                case .alwaysUv:
                    SinglePinSheet(title: "Confirm PIN to toggle alwaysUV", remembered: session.rememberedPin) { pin, remember in
                        if remember { session.rememberPin(pin) }
                        Task { await session.fidoToggleAlwaysUv(pin: pin) }
                    }
                case .minPin, .minPinAlpha:
                    MinPinSheet(alphanumeric: which == .minPinAlpha,
                                current: which == .minPin ? info0?.minPinLength : nil,
                                remembered: session.rememberedPin) { pin, length, remember in
                        if remember { session.rememberPin(pin) }
                        Task { await session.fidoSetMinPinLength(pin: pin, length: length, alphanumeric: which == .minPinAlpha) }
                    }
                case .listFingerprints:
                    SinglePinSheet(title: "Enter PIN to manage fingerprints", remembered: session.rememberedPin) { pin, remember in
                        if remember { session.rememberPin(pin) }
                        Task {
                            await session.fidoListFingerprints(pin: pin)
                            if session.fidoError == nil { showFingerprintManager = true }
                        }
                    }
                case .listPasskeys:
                    SinglePinSheet(title: "Enter PIN to list passkeys", remembered: session.rememberedPin) { pin, remember in
                        if remember { session.rememberPin(pin) }
                        Task {
                            await session.fidoListPasskeys(pin: pin)
                            if session.fidoError == nil { showPasskeyManager = true }
                        }
                    }
                }
            }
            .sheet(isPresented: $showPasskeyManager) {
                PasskeyManagerView()
            }
            .sheet(isPresented: $showFingerprintManager) {
                FingerprintManagerView()
            }
            .confirmationDialog("Reset FIDO2?", isPresented: $confirmReset, titleVisibility: .visible) {
                Button("Erase passkeys, fingerprints and PIN", role: .destructive) {
                    Task { await session.fidoReset() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This can't be undone. Accounts that use this key's passkeys will need another way to sign in.")
            }
        }
    }

    private var info0: Ctap2Client.Info? { session.fidoInfo }

    @ViewBuilder
    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }
}

/// A PIN field with a numeric-vs-alphanumeric keyboard toggle, matching the
/// Android dialog: numeric password keyboard by default, a "Letters & symbols"
/// switch to allow text PINs.
struct PinField: View {
    let placeholder: String
    @Binding var text: String
    @Binding var alphanumeric: Bool
    /// Focus this field and raise the keyboard when the sheet appears.
    var autoFocus: Bool = false

    var body: some View {
        // UIKit-backed: switches keypads in place and reliably shows the keyboard.
        PinTextField(placeholder: placeholder, text: $text, alphanumeric: alphanumeric, autoFocus: autoFocus)
    }
}

/// PIN entry with an optional "current PIN" field (for change). Includes the
/// keyboard-type toggle and "remember this session" switch from the Android UI.
private struct PinSheet: View {
    let title: String
    let needsOld: Bool
    let onSubmit: (_ old: String, _ new: String, _ remember: Bool) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var oldPin = ""
    @State private var newPin = ""
    @State private var confirmPin = ""
    @AppStorage("pinKeyboardAlphanumeric") private var alphanumeric = false
    @State private var remember = false

    private var valid: Bool {
        let lenOk = (4...63).contains(newPin.utf8.count) && newPin == confirmPin
        return needsOld ? (!oldPin.isEmpty && lenOk) : lenOk
    }

    var body: some View {
        NavigationStack {
            Form {
                if needsOld {
                    Section("Current PIN") {
                        PinField(placeholder: "Current PIN", text: $oldPin, alphanumeric: $alphanumeric, autoFocus: true)
                    }
                }
                Section("New PIN") {
                    PinField(placeholder: "New PIN (4–63 chars)", text: $newPin, alphanumeric: $alphanumeric, autoFocus: !needsOld)
                    PinField(placeholder: "Confirm new PIN", text: $confirmPin, alphanumeric: $alphanumeric)
                }
                if !newPin.isEmpty && newPin != confirmPin {
                    Text("PINs don't match.").font(.footnote).foregroundStyle(.orange)
                }
                Section {
                    Toggle("Letters & symbols", isOn: $alphanumeric)
                    Toggle("Remember PIN this session", isOn: $remember)
                } footer: {
                    Text("Remembered only in memory, never saved to disk.")
                }
            }
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { onSubmit(oldPin, newPin, remember); dismiss() }.disabled(!valid)
                }
            }
        }
    }
}

/// Single PIN field (for confirm-style actions). Prefills a remembered PIN if
/// present, and offers the keyboard toggle + remember switch.
struct SinglePinSheet: View {
    let title: String
    let remembered: String?
    let onSubmit: (_ pin: String, _ remember: Bool) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var pin = ""
    @AppStorage("pinKeyboardAlphanumeric") private var alphanumeric = false
    @State private var remember = false

    var body: some View {
        NavigationStack {
            Form {
                Section { PinField(placeholder: "PIN", text: $pin, alphanumeric: $alphanumeric, autoFocus: true) }
                Section {
                    Toggle("Letters & symbols", isOn: $alphanumeric)
                    Toggle("Remember PIN this session", isOn: $remember)
                } footer: {
                    Text("Remembered only in memory, never saved to disk.")
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { if let r = remembered { pin = r } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue") { onSubmit(pin, remember); dismiss() }.disabled(pin.isEmpty)
                }
            }
        }
    }
}

/// Minimum PIN length entry. CTAP only lets the minimum grow; lowering it takes
/// a reset. The alphanumeric variant sets the separate minimum for PINs that
/// contain letters or symbols.
private struct MinPinSheet: View {
    let alphanumeric: Bool
    let current: Int?
    let remembered: String?
    let onSubmit: (_ pin: String, _ length: Int, _ remember: Bool) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var length = 6
    @State private var pin = ""
    @AppStorage("pinKeyboardAlphanumeric") private var pinAlphanumeric = false
    @State private var remember = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Stepper(value: $length, in: max(4, current ?? 4)...63) {
                        Text("\(length) characters")
                    }
                } header: {
                    Text(alphanumeric ? "Minimum for PINs with letters or symbols" : "Minimum PIN length")
                } footer: {
                    Text("The minimum can only be raised. Lowering it again requires a FIDO2 reset. If the current PIN is shorter, the key will ask for a PIN change.")
                }
                Section("Current PIN") {
                    PinField(placeholder: "PIN", text: $pin, alphanumeric: $pinAlphanumeric, autoFocus: true)
                }
                Section {
                    Toggle("Letters & symbols", isOn: $pinAlphanumeric)
                    Toggle("Remember PIN this session", isOn: $remember)
                } footer: {
                    Text("Remembered only in memory, never saved to disk.")
                }
            }
            .navigationTitle(alphanumeric ? "Alphanumeric minimum" : "Minimum PIN length")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                if let r = remembered { pin = r }
                if let c = current { length = max(c, 4) }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Set") { onSubmit(pin, length, remember); dismiss() }.disabled(pin.isEmpty)
                }
            }
        }
    }
}
