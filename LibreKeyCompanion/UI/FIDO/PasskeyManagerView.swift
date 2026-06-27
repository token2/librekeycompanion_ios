import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// Dedicated passkey management screen, presented from the FIDO2 tab. Lists all
/// discoverable credentials with relying party + user, opens a full detail popup
/// (all fields from the Android app), and deletes with an "are you sure"
/// confirmation followed by a PIN prompt. Mirrors the Android passkey pane.
struct PasskeyManagerView: View {
    @EnvironmentObject var session: KeySession
    @Environment(\.dismiss) private var dismiss

    @State private var detail: Ctap2Client.Passkey?
    @State private var pendingDelete: Ctap2Client.Passkey?
    @State private var deletePinFor: Ctap2Client.Passkey?

    var body: some View {
        NavigationStack {
            List {
                if let msg = session.fidoMessage {
                    Section { Text(msg).foregroundStyle(.green).font(.callout) }
                }
                if let err = session.fidoError {
                    Section { Text(err).foregroundStyle(.orange).font(.callout) }
                }

                if session.passkeys.isEmpty {
                    Section {
                        Text("No passkeys, or none read yet. Pull to refresh, or re-list from the FIDO2 tab.")
                            .foregroundStyle(.secondary).font(.callout)
                    }
                } else {
                    Section("Passkeys (\(session.passkeys.count))") {
                        ForEach(session.passkeys.indices, id: \.self) { i in
                            let p = session.passkeys[i]
                            Button {
                                detail = p
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(p.rpId).font(.headline).foregroundStyle(.primary)
                                    Text(p.userDisplayName ?? p.userName ?? "(no user name)")
                                        .font(.subheadline).foregroundStyle(.secondary)
                                }
                            }
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) {
                                    pendingDelete = p
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Passkeys")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { Button("Done") { dismiss() } }
            }
            .sheet(item: $detail) { p in
                PasskeyDetailView(passkey: p)
            }
            // "Are you sure" confirmation, then PIN.
            .confirmationDialog(
                deletePrompt,
                isPresented: deleteDialogBinding,
                titleVisibility: .visible
            ) {
                Button("Delete passkey", role: .destructive) {
                    // Hand the passkey to the PIN sheet directly, then clear the
                    // confirmation state. The sheet binds to its own item, so it
                    // can't lose the passkey when this dialog dismisses.
                    deletePinFor = pendingDelete
                    pendingDelete = nil
                }
                Button("Cancel", role: .cancel) { pendingDelete = nil }
            }
            .sheet(item: $deletePinFor) { passkey in
                DeletePinSheet(remembered: session.rememberedPin) { pin, remember in
                    if remember { session.rememberPin(pin) }
                    Task { await session.fidoDeletePasskey(pin: pin, credentialId: passkey.credentialId) }
                }
            }
        }
    }

    private func displayName(_ p: Ctap2Client.Passkey) -> String {
        p.userDisplayName ?? p.userName ?? p.rpId
    }

    /// Confirmation message for deleting the pending passkey.
    private var deletePrompt: String {
        guard let p = pendingDelete else { return "" }
        return "Delete \"\(displayName(p))\" from \(p.rpId)? This can't be undone."
    }

    /// Binding driving the delete confirmation dialog's presentation.
    private var deleteDialogBinding: Binding<Bool> {
        Binding(get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } })
    }
}

/// Make Passkey identifiable for the detail sheet (credentialId is unique).
extension Ctap2Client.Passkey: Identifiable {
    var id: String { credentialId.base64EncodedString() }
}

/// Full passkey detail popup — every field the Android info dialog showed.
private struct PasskeyDetailView: View {
    let passkey: Ctap2Client.Passkey
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            List {
                detailRow("Relying party", passkey.rpId)
                detailRow("User name", passkey.userName ?? "—")
                detailRow("Display name", passkey.userDisplayName ?? "—")
                detailRow("User handle", truncate(passkey.userHandleHex, 32))
                detailRow("Algorithm", algoName(passkey.algorithm))
                detailRow("Credential protection", credProtectName(passkey.credProtect))
                detailRow("Credential ID", truncate(passkey.credentialIdB64Url, 28))

                Section {
                    Button {
                        #if canImport(UIKit)
                        UIPasteboard.general.string = passkey.credentialIdB64Url
                        #endif
                        copied = true
                    } label: {
                        Label(copied ? "Copied" : "Copy credential ID",
                              systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc")
                    }
                }
            }
            .navigationTitle(passkey.userDisplayName ?? passkey.userName ?? passkey.rpId)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Close") { dismiss() } }
            }
        }
    }

    @ViewBuilder
    private func detailRow(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.body).textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }

    private func truncate(_ s: String?, _ n: Int) -> String {
        guard let s, !s.isEmpty else { return "—" }
        return s.count > n ? String(s.prefix(n)) + "…" : s
    }

    private func algoName(_ a: Int?) -> String {
        switch a {
        case -7: return "ES256 (ECDSA P-256)"
        case -8: return "EdDSA (Ed25519)"
        case -35: return "ES384 (ECDSA P-384)"
        case -36: return "ES512 (ECDSA P-521)"
        case -257: return "RS256 (RSA)"
        case nil: return "—"
        case .some(let v): return "alg \(v)"
        }
    }

    private func credProtectName(_ c: Int?) -> String {
        switch c {
        case 1: return "Optional (uvOptional)"
        case 2: return "Optional with credential ID"
        case 3: return "Required (uvRequired)"
        case nil: return "—"
        case .some(let v): return "level \(v)"
        }
    }
}

/// PIN sheet specialized for delete confirmation (numeric keyboard + toggles).
private struct DeletePinSheet: View {
    let remembered: String?
    let onSubmit: (_ pin: String, _ remember: Bool) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var pin = ""
    @AppStorage("pinKeyboardAlphanumeric") private var alphanumeric = false
    @State private var remember = false
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section("Confirm with PIN") {
                    SecureField("PIN", text: $pin)
                        .keyboardType(alphanumeric ? .default : .numberPad)
                        .textContentType(.password)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .focused($focused)
                        .id(alphanumeric)
                        .onChange(of: alphanumeric) { _ in focused = true }
                }
                Section {
                    Toggle("Letters & symbols", isOn: $alphanumeric)
                    Toggle("Remember PIN this session", isOn: $remember)
                } footer: {
                    Text("Enter the key's PIN to delete this passkey. Remembered only in memory.")
                }
            }
            .navigationTitle("Delete passkey")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { if let r = remembered { pin = r } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Delete") { onSubmit(pin, remember); dismiss() }.disabled(pin.isEmpty)
                }
            }
        }
    }
}
