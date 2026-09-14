import SwiftUI

/// PIN entry sheet for the Token2 OTP PIN (privacy protection). One sheet serves
/// unlock / set / change / remove; which fields show depends on `kind`.
struct Token2PinSheet: View {
    @EnvironmentObject var session: KeySession
    @Environment(\.dismiss) private var dismiss

    let kind: KeySession.OtpPinPrompt.Kind

    @State private var current = ""
    @State private var newPin = ""
    @State private var confirm = ""
    @State private var alphaKeypad = false
    @State private var remember = false
    @State private var validationError: String?

    /// AppStorage remembers the keypad-type preference between prompts.
    @AppStorage("otp_pin_alpha_keypad") private var storedAlpha = false

    private var title: String {
        switch kind {
        case .unlock: return "Enter OTP PIN"
        case .set:    return "Set OTP PIN"
        case .change: return "Change OTP PIN"
        case .remove: return "Remove OTP PIN"
        case .enableFingerprint:  return "Enable Fingerprint Unlock"
        case .disableFingerprint: return "Disable Fingerprint Unlock"
        }
    }

    private var keyboardType: UIKeyboardType { alphaKeypad ? .asciiCapable : .numberPad }

    var body: some View {
        NavigationStack {
            Form {
                if kind == .change || kind == .remove {
                    Section("Current PIN") {
                        SecureField("Current PIN", text: $current)
                            .keyboardType(keyboardType)
                            .textContentType(.password)
                    }
                }
                if kind == .set || kind == .change {
                    Section(kind == .set ? "New PIN" : "New PIN") {
                        SecureField("New PIN", text: $newPin)
                            .keyboardType(keyboardType)
                        SecureField("Confirm new PIN", text: $confirm)
                            .keyboardType(keyboardType)
                    }
                }
                if kind == .enableFingerprint || kind == .disableFingerprint {
                    Section {
                        SecureField("OTP PIN", text: $newPin)
                            .keyboardType(keyboardType)
                            .textContentType(.password)
                    } header: {
                        Text("OTP PIN")
                    } footer: {
                        Text(kind == .enableFingerprint
                            ? "Enrol a fingerprint in the key's FIDO2 setup first. Enter your OTP PIN to turn on fingerprint unlock."
                            : "Enter your OTP PIN to turn off fingerprint unlock.")
                    }
                }
                if kind == .unlock {
                    if session.otpFingerprintUnlockAvailable {
                        Section {
                            Button {
                                dismiss()
                                Task { await session.otpUnlockWithFingerprint() }
                            } label: {
                                Label("Unlock with fingerprint", systemImage: "touchid")
                                    .frame(maxWidth: .infinity)
                            }
                            .disabled(session.isScanning)
                        } footer: {
                            Text("Touch the sensor on the plugged-in key, or enter the PIN below — either one unlocks.")
                        }
                    }
                    Section("OTP PIN") {
                        SecureField("OTP PIN", text: $newPin)
                            .keyboardType(keyboardType)
                            .textContentType(.password)
                    }
                }

                Section {
                    Toggle("Full keyboard (letters & symbols)", isOn: $alphaKeypad)
                    if kind == .unlock {
                        Toggle("Remember PIN until app closes", isOn: $remember)
                    }
                } footer: {
                    if kind == .set || kind == .change {
                        Text("Numeric PINs need ≥6 digits; alphanumeric ≥10 characters.")
                    } else if kind == .unlock {
                        Text("The PIN is kept in memory only, never saved to disk.")
                    }
                }

                if let err = validationError {
                    Section { Text(err).foregroundStyle(.red).font(.callout) }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { alphaKeypad = storedAlpha }
            .onChange(of: alphaKeypad) { storedAlpha = $0 }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(primaryLabel) { submit() }
                        .disabled(session.isScanning)
                }
            }
        }
    }

    private var primaryLabel: String {
        switch kind {
        case .unlock: return "Unlock"
        case .set:    return "Set"
        case .change: return "Change"
        case .remove: return "Remove"
        case .enableFingerprint:  return "Enable"
        case .disableFingerprint: return "Disable"
        }
    }

    private func submit() {
        validationError = nil
        switch kind {
        case .unlock:
            guard !newPin.isEmpty else { validationError = "Enter your OTP PIN."; return }
            let pin = newPin, rem = remember
            dismiss()
            Task { await session.otpUnlock(pin: pin, remember: rem) }
        case .set:
            if let e = Token2PinValidator.validate(newPin) { validationError = e; return }
            guard newPin == confirm else { validationError = "PINs did not match."; return }
            let pin = newPin
            dismiss()
            Task { await session.otpSetPin(pin) }
        case .change:
            guard !current.isEmpty else { validationError = "Enter your current PIN."; return }
            if let e = Token2PinValidator.validate(newPin) { validationError = e; return }
            guard newPin == confirm else { validationError = "New PINs did not match."; return }
            let cur = current, np = newPin
            dismiss()
            Task { await session.otpChangePin(current: cur, new: np) }
        case .remove:
            guard !current.isEmpty else { validationError = "Enter your current PIN."; return }
            let cur = current
            dismiss()
            Task { await session.otpRemovePin(current: cur) }
        case .enableFingerprint, .disableFingerprint:
            guard !newPin.isEmpty else { validationError = "Enter your OTP PIN."; return }
            let pin = newPin, enable = (kind == .enableFingerprint)
            dismiss()
            Task { await session.otpSetFingerprintProtection(pin: pin, enable: enable) }
        }
    }
}
