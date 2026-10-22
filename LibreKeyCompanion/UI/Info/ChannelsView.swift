import SwiftUI

/// Token2 USB channel settings (FIDO / HID-HOTP / CCID), like Device Settings in
/// the Token2 desktop tools. Reads the current state when opened; Apply sends
/// SET_DEVICE_TYPE and the key restarts to take it. NFC isn't affected.
struct ChannelsView: View {
    @EnvironmentObject var session: KeySession
    @Environment(\.dismiss) private var dismiss

    @State private var draft = Token2OTPApplet.Channels(fido: true, hidHotp: false, ccid: true)
    @State private var loaded = false
    @State private var confirmApply = false

    private var current: Token2OTPApplet.Channels? { session.token2Channels }
    private var changed: Bool { loaded && current != nil && draft != current }
    private var tooFew: Bool { draft.enabledCount < 2 }
    private var onUSB: Bool { session.transportMode == .usb }

    var body: some View {
        NavigationStack {
            Form {
                if let msg = session.channelsMessage {
                    Section { Text(msg).foregroundStyle(.green).font(.callout) }
                }
                if let err = session.channelsError {
                    Section { Text(err).foregroundStyle(.orange).font(.callout) }
                }

                if loaded, current != nil {
                    Section {
                        Toggle(isOn: $draft.fido) {
                            channelLabel("FIDO", "Passkeys and security-key sign-in in browsers and apps.")
                        }
                        Toggle(isOn: $draft.hidHotp) {
                            channelLabel("HID-HOTP", "Types an HOTP code when the key's button is touched (acts as a keyboard).")
                        }
                        Toggle(isOn: $draft.ccid) {
                            channelLabel("CCID", "Smart card: OTP, PIV, OpenPGP — and how this app reaches the key over USB-C.")
                        }
                    } header: {
                        Text("USB channels")
                    } footer: {
                        Text("Disabling a channel turns off the matching USB function. At least two channels must stay on. NFC is not affected. HID-HOTP is off by default from Release 3.3.")
                    }

                    if tooFew {
                        Section { Text("Keep at least two channels enabled.").foregroundStyle(.orange).font(.callout) }
                    } else if !draft.ccid && current?.ccid == true {
                        Section {
                            Text(onUSB
                                 ? "With CCID off, this app can no longer reach the key over USB-C. You can still turn it back on over NFC (if the key has NFC) or from a computer."
                                 : "With CCID off, apps can't reach the key as a smart card over USB (OTP, PIV, OpenPGP). NFC keeps working.")
                                .font(.callout)
                        }
                    }

                    Section {
                        Button("Apply") { confirmApply = true }
                            .disabled(!changed || tooFew || session.channelsBusy)
                        Button("Re-read") { Task { await reload() } }
                            .disabled(session.channelsBusy)
                    }
                } else {
                    Section {
                        if session.channelsBusy {
                            HStack(spacing: 12) { ProgressView(); Text("Reading channels…") }
                        } else {
                            Button("Read channels") { Task { await reload() } }
                        }
                    } footer: {
                        Text(onUSB ? "Reads from the plugged-in key." : "Hold the key near the phone when asked.")
                    }
                }
            }
            .navigationTitle("USB channels")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .task { if !loaded { await reload() } }
            .onChange(of: session.token2Channels) { c in
                if let c { draft = c; loaded = true }
            }
            .confirmationDialog("Apply channel settings?", isPresented: $confirmApply, titleVisibility: .visible) {
                Button("Apply and restart key") { Task { await session.applyChannels(draft) } }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(summary)
            }
        }
    }

    private func reload() async {
        session.channelsMessage = nil
        await session.readChannels()
        if let c = session.token2Channels { draft = c; loaded = true }
    }

    private var summary: String {
        func s(_ on: Bool) -> String { on ? "on" : "off" }
        return "FIDO \(s(draft.fido)), HID-HOTP \(s(draft.hidHotp)), CCID \(s(draft.ccid)). The key restarts to apply the change."
    }

    @ViewBuilder
    private func channelLabel(_ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }
    }
}
