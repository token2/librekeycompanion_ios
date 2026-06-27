import SwiftUI

/// FIDO2 management tab: authenticator info, PIN set/change, alwaysUV toggle,
/// and passkey list/delete — each runs over one NFC tap. PIN-gated actions
/// prompt for the PIN. Mirrors the Android FIDO2 screen (minus fingerprint
/// enrollment, which needs a held USB session unavailable on iOS).
struct FIDOView: View {
    @EnvironmentObject var session: KeySession
    @EnvironmentObject var mds: MDSRepository
    @State private var sheet: ActiveSheet?
    @State private var showPasskeyManager = false

    enum ActiveSheet: Identifiable {
        case setPin, changePin, alwaysUv, listPasskeys
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

                if let info = session.fidoInfo {
                    if let a = info.aaguidHex, let entry = mds.lookup(aaguid: a) {
                        Section {
                            DeviceHeaderCard(entry: entry)
                        }
                    }
                    Section("Authenticator") {
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
        }
    }

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
private struct PinField: View {
    let placeholder: String
    @Binding var text: String
    @Binding var alphanumeric: Bool

    @FocusState private var focused: Bool

    var body: some View {
        SecureField(placeholder, text: $text)
            .keyboardType(alphanumeric ? .default : .numberPad)
            .textContentType(.password)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .focused($focused)
            // Changing the identity forces SwiftUI to rebuild the field so the new
            // keyboard type is applied immediately (a live `.keyboardType` change
            // is otherwise ignored while the keyboard is already on screen). The
            // text is preserved by the binding; we re-focus to keep the keyboard up.
            .id(alphanumeric)
            .onChange(of: alphanumeric) { _ in
                focused = true
            }
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
                        PinField(placeholder: "Current PIN", text: $oldPin, alphanumeric: $alphanumeric)
                    }
                }
                Section("New PIN") {
                    PinField(placeholder: "New PIN (4–63 chars)", text: $newPin, alphanumeric: $alphanumeric)
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
private struct SinglePinSheet: View {
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
                Section { PinField(placeholder: "PIN", text: $pin, alphanumeric: $alphanumeric) }
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
