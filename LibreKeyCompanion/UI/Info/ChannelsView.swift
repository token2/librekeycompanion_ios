import SwiftUI

/// Token2 USB channel settings. Shows the FIDO / HID-HOTP / CCID state; only
/// HID-HOTP can be switched here. FIDO and CCID are status-only — changing them
/// can cut off browsers or this app, so that's left to the desktop tools.
/// Apply sends SET_DEVICE_TYPE and the key restarts to take it. NFC isn't affected.
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

                if loaded, let cur = current {
                    Section {
                        Toggle(isOn: $draft.hidHotp) {
                            channelLabel("HID-HOTP", "Types an HOTP code when the key's button is touched. While it's on, iOS treats the plugged-in key as a keyboard and hides the on-screen keyboard.")
                        }
                    } header: {
                        Text("Keyboard channel")
                    } footer: {
                        Text("Off by default from Release 3.3. Turn it on only if you use button-press HOTP (for example with UserLock).")
                    }

                    Section {
                        statusRow("FIDO", "Passkeys and security-key sign-in.", on: cur.fido)
                        statusRow("CCID", "Smart card: OTP, PIV, OpenPGP, and this app over USB-C.", on: cur.ccid)
                    } header: {
                        Text("Other channels")
                    } footer: {
                        Text("Shown for information. These normally stay on; if you ever need to change them, use Token2 Key Manager on a computer.")
                    }

                    if tooFew {
                        Section {
                            Text("At least two channels must stay on. Turn FIDO or CCID back on from a computer first.")
                                .foregroundStyle(.orange).font(.callout)
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
                Button("Apply and restart key") {
                    guard let cur = current else { return }
                    var c = cur; c.hidHotp = draft.hidHotp
                    Task { await session.applyChannels(c) }
                }
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
        "HID-HOTP will be turned \(draft.hidHotp ? "on" : "off"). The key restarts to apply the change."
    }

    @ViewBuilder
    private func statusRow(_ title: String, _ detail: String, on: Bool) -> some View {
        HStack {
            channelLabel(title, detail)
            Spacer()
            Text(on ? "On" : "Off").foregroundStyle(on ? Color.green : Color.orange)
        }
    }

    @ViewBuilder
    private func channelLabel(_ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }
    }
}
