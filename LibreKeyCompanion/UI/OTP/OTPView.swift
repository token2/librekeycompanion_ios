import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// OTP tab: trigger an NFC read, show live TOTP codes with a countdown, copy a
/// code by tapping it, delete by swiping, and add entries via the manual form.
struct OTPView: View {
    @EnvironmentObject var session: KeySession
    var isActive: Bool = false
    @State private var showAdd = false
    @State private var entryFields = OTPEntryFields()
    @State private var copiedId: String?
    @State private var pendingDelete: KeySession.LiveCode?

    /// Copy a code's digits to the clipboard and flash a "Copied" state.
    private func copyCode(_ c: KeySession.LiveCode) {
        let digits = c.code.filter(\.isNumber)
        guard !digits.isEmpty else { return }      // nothing to copy (e.g. touch-required)
        #if canImport(UIKit)
        UIPasteboard.general.string = digits
        #endif
        copiedId = c.id
        Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            if copiedId == c.id { copiedId = nil }
        }
    }

    /// Confirmation message for deleting the pending OTP entry.
    private var deletePrompt: String {
        guard let c = pendingDelete else { return "" }
        let prefix = c.issuer.map { "\($0): " } ?? ""
        return "Delete \(prefix)\(c.account)? This removes it from the key and can't be undone."
    }

    /// Binding that drives the delete confirmation dialog's presentation.
    private var deleteDialogBinding: Binding<Bool> {
        Binding(get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } })
    }

    /// One credential row: tap to copy, swipe to delete (with confirmation).
    @ViewBuilder
    private func credentialRow(_ c: KeySession.LiveCode) -> some View {
        CodeRow(code: c, copied: copiedId == c.id)
            .contentShape(Rectangle())
            .onTapGesture {
                if c.touchRequired {
                    Task { await session.revealTouchCode(id: c.id) }
                } else {
                    copyCode(c)
                }
            }
            .swipeActions(edge: .trailing) {
                Button(role: .destructive) {
                    pendingDelete = c
                } label: {
                    Label("Delete", systemImage: "trash")
                }
            }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    TransportPicker()
                    Button {
                        Task { await session.scanOATH() }
                    } label: {
                        Label(session.isScanning ? "Reading…" : "Read Device",
                              systemImage: "wave.3.right")
                    }
                    .disabled(session.isScanning)
                }

                if let err = session.errorMessage {
                    Section {
                        Text(err).foregroundStyle(.red).font(.callout)
                    }
                }

                if !session.credentials.isEmpty {
                    Section {
                        ForEach(session.credentials) { c in
                            credentialRow(c)
                        }
                    } header: {
                        Text("Credentials")
                    } footer: {
                        Text("Tap a code to copy it. Rows marked with the tap icon need a button press — tap the row, then touch your key to reveal the code. Swipe left to delete.")
                    }
                }
            }
            .navigationTitle("OTP")
            .onChange(of: session.usbCardReady) { ready in
                if ready && isActive && session.credentials.isEmpty {
                    Task { await session.scanOATH(); session.clearUSBReadyFlag() }
                }
            }
            .onChange(of: isActive) { active in
                if active && session.usbCardReady && session.credentials.isEmpty {
                    Task { await session.scanOATH(); session.clearUSBReadyFlag() }
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { entryFields = OTPEntryFields(); showAdd = true } label: { Image(systemName: "plus") }
                }
            }
            .overlay {
                if session.credentials.isEmpty && !session.isScanning && session.errorMessage == nil {
                    EmptyStateView(
                        title: "No codes yet",
                        systemImage: "clock.badge.questionmark",
                        message: session.statusMessage)
                }
            }
            .overlay {
                if let prompt = session.touchPrompt {
                    TouchPromptDialog(message: prompt)
                }
            }
            .animation(.easeInOut(duration: 0.2), value: session.touchPrompt)
            .sheet(isPresented: $showAdd) {
                AddEntryForm(fields: $entryFields) { fields in
                    Task { await session.addEntry(fields) }
                }
            }
            .confirmationDialog(
                deletePrompt,
                isPresented: deleteDialogBinding,
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    if let c = pendingDelete {
                        Task { await session.deleteCredential(id: c.id) }
                    }
                    pendingDelete = nil
                }
                Button("Cancel", role: .cancel) { pendingDelete = nil }
            }
        }
    }
}

/// An iOS 16-compatible replacement for `ContentUnavailableView` (iOS 17+).
/// Renders a centered icon, title, and message, matching the system look.
private struct EmptyStateView: View {
    let title: String
    let systemImage: String
    let message: String

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 48, weight: .light))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.title3.weight(.semibold))
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct CodeRow: View {
    let code: KeySession.LiveCode
    var copied: Bool = false
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                if let issuer = code.issuer {
                    Text(issuer).font(.headline)
                }
                Text(code.account).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
            if copied {
                Label("Copied", systemImage: "checkmark.circle.fill")
                    .font(.subheadline)
                    .foregroundStyle(.green)
                    .labelStyle(.titleAndIcon)
            } else if code.touchRequired {
                Image(systemName: "hand.tap.fill")
                    .font(.body)
                    .foregroundStyle(.orange)
            } else {
                Text(code.code)
                    .font(.system(.title3, design: .monospaced))
                    .monospacedDigit()
                if code.secondsRemaining > 0 {
                    CountdownRing(seconds: code.secondsRemaining)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

private struct CountdownRing: View {
    let seconds: Int
    var body: some View {
        ZStack {
            Circle().stroke(.quaternary, lineWidth: 3).frame(width: 26, height: 26)
            Circle()
                .trim(from: 0, to: CGFloat(seconds) / 30.0)
                .stroke(.tint, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .frame(width: 26, height: 26)
            Text("\(seconds)").font(.caption2).monospacedDigit()
        }
    }
}
