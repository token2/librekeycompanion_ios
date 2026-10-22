import SwiftUI

/// Fingerprint management, presented from the FIDO2 tab after a PIN-gated list:
/// enrolled fingerprints with rename and delete, plus enrollment of a new one.
/// Enrollment needs several touches in one held session, so it's offered only
/// when the key is connected over USB-C.
struct FingerprintManagerView: View {
    @EnvironmentObject var session: KeySession
    @Environment(\.dismiss) private var dismiss

    @State private var renaming: Ctap2Client.Fingerprint?
    @State private var pendingDelete: Ctap2Client.Fingerprint?
    @State private var deleting: Ctap2Client.Fingerprint?
    @State private var showEnroll = false

    var body: some View {
        NavigationStack {
            List {
                if let msg = session.fidoMessage {
                    Section { Text(msg).foregroundStyle(.green).font(.callout) }
                }
                if let err = session.fidoError {
                    Section { Text(err).foregroundStyle(.orange).font(.callout) }
                }

                Section {
                    if session.fingerprints.isEmpty {
                        Text("No fingerprints enrolled.").foregroundStyle(.secondary).font(.callout)
                    }
                    ForEach(Array(session.fingerprints.enumerated()), id: \.offset) { i, fp in
                        Button {
                            renaming = fp
                        } label: {
                            HStack {
                                Image(systemName: "touchid").foregroundStyle(.tint)
                                Text(fp.name?.isEmpty == false ? fp.name! : "Fingerprint \(i + 1)")
                                    .foregroundStyle(.primary)
                            }
                        }
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) { pendingDelete = fp } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                    }
                } header: {
                    Text("Enrolled (\(session.fingerprints.count))")
                } footer: {
                    Text("Tap a fingerprint to rename it, swipe to delete.")
                }

                Section {
                    Button {
                        showEnroll = true
                    } label: {
                        Label("Add fingerprint", systemImage: "plus.circle")
                    }
                    .disabled(!session.fidoOverUSB || session.fidoBusy)
                } footer: {
                    if !session.fidoOverUSB {
                        Text("Plug the key in over USB-C to enroll a new fingerprint.")
                    }
                }
            }
            .navigationTitle("Fingerprints")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { Button("Done") { dismiss() } }
            }
            .sheet(item: $renaming) { fp in
                RenameFingerprintSheet(initialName: fp.name ?? "", remembered: session.rememberedPin) { pin, name, remember in
                    if remember { session.rememberPin(pin) }
                    Task { await session.fidoRenameFingerprint(pin: pin, templateId: fp.templateId, name: name) }
                }
            }
            .confirmationDialog("Delete this fingerprint?", isPresented: deleteDialogBinding, titleVisibility: .visible) {
                Button("Delete fingerprint", role: .destructive) {
                    deleting = pendingDelete
                    pendingDelete = nil
                }
                Button("Cancel", role: .cancel) { pendingDelete = nil }
            }
            .sheet(item: $deleting) { fp in
                SinglePinSheet(title: "Enter PIN to delete", remembered: session.rememberedPin) { pin, remember in
                    if remember { session.rememberPin(pin) }
                    Task { await session.fidoRemoveFingerprint(pin: pin, templateId: fp.templateId) }
                }
            }
            .sheet(isPresented: $showEnroll) {
                EnrollFingerprintSheet()
            }
        }
    }

    private var deleteDialogBinding: Binding<Bool> {
        Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } })
    }
}

private struct RenameFingerprintSheet: View {
    let initialName: String
    let remembered: String?
    let onSubmit: (_ pin: String, _ name: String, _ remember: Bool) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var pin = ""
    @AppStorage("pinKeyboardAlphanumeric") private var alphanumeric = false
    @State private var remember = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") {
                    TextField("e.g. Right index", text: $name)
                        .autocorrectionDisabled()
                }
                Section("PIN") {
                    PinField(placeholder: "PIN", text: $pin, alphanumeric: $alphanumeric)
                }
                Section {
                    Toggle("Letters & symbols", isOn: $alphanumeric)
                    Toggle("Remember PIN this session", isOn: $remember)
                }
            }
            .navigationTitle("Rename fingerprint")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                name = initialName
                if let r = remembered { pin = r }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { onSubmit(pin, name, remember); dismiss() }
                        .disabled(pin.isEmpty || name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }
}

/// Two-step enrollment sheet: name + PIN, then live progress while the user
/// touches the sensor repeatedly.
private struct EnrollFingerprintSheet: View {
    @EnvironmentObject var session: KeySession
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var pin = ""
    @AppStorage("pinKeyboardAlphanumeric") private var alphanumeric = false
    @State private var started = false

    var body: some View {
        NavigationStack {
            Form {
                if !started {
                    Section("Name (optional)") {
                        TextField("e.g. Right index", text: $name).autocorrectionDisabled()
                    }
                    Section {
                        PinField(placeholder: "PIN", text: $pin, alphanumeric: $alphanumeric, autoFocus: true)
                        Toggle("Letters & symbols", isOn: $alphanumeric)
                    } header: {
                        Text("PIN")
                    } footer: {
                        Text("Keep the key plugged in. You'll touch the sensor several times, lifting your finger between touches.")
                    }
                } else {
                    progressSection
                }
            }
            .navigationTitle("Add fingerprint")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { if let r = session.rememberedPin { pin = r } }
            .interactiveDismissDisabled(session.fidoBusy)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if started && session.fidoBusy {
                        Button("Stop") { session.fidoCancelEnrollment() }
                    } else {
                        Button(started ? "Close" : "Cancel") { dismiss() }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if !started {
                        Button("Start") {
                            started = true
                            Task { await session.fidoEnrollFingerprint(pin: pin, name: name) }
                        }
                        .disabled(pin.isEmpty)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var progressSection: some View {
        Section {
            if let p = session.enrollProgress {
                if p.finished {
                    Label("Fingerprint enrolled", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                } else {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text("Touch the sensor on the key").font(.headline)
                    }
                }
                if let remaining = p.remaining, !p.finished {
                    ProgressView(value: Double(p.samplesDone), total: Double(max(1, p.samplesDone + remaining)))
                    Text("\(p.samplesDone) good sample(s), \(remaining) to go").font(.callout).foregroundStyle(.secondary)
                }
                if let status = p.lastStatus, !p.finished {
                    Text(status).font(.callout)
                }
            } else if let err = session.fidoError {
                Text(err).foregroundStyle(.orange).font(.callout)
            } else if let msg = session.fidoMessage {
                Text(msg).font(.callout)
            } else {
                HStack(spacing: 12) { ProgressView(); Text("Starting…") }
            }
        }
    }
}
