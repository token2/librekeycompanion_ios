import SwiftUI

/// Info tab: read a key once (explicit button) and show which applets it exposes.
/// OATH, FIDO2, and Token2 show a green check when present; PIV and OpenPGP show
/// a read-only status that opens a detail popup.
struct InfoView: View {
    @EnvironmentObject var session: KeySession
    @EnvironmentObject var mds: MDSRepository
    var isActive: Bool = false
    var selectedTab: Binding<Int>? = nil
    @State private var showPiv = false
    @State private var showPgp = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: 14) {
                        Image("Logo").resizable().frame(width: 48, height: 48)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Libre Key Companion").font(.headline)
                            Text("Manage hardware security keys and cards")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                    .listRowBackground(Color.clear)
                }

                Section {
                    TransportPicker()
                    Button {
                        Task { await session.scanInfo() }
                    } label: {
                        Label(session.infoBusy ? "Reading…" : "Read Device",
                              systemImage: "wave.3.right")
                    }
                    .disabled(session.infoBusy)
                } footer: {
                    Text("Reads the key and lists what it supports. Over NFC, hold the key to the top of the phone. Over USB-C, the key stays plugged in. FIDO2 is read over NFC only.")
                }

                if let err = session.infoError {
                    Section { Text(err).foregroundStyle(.orange).font(.callout) }
                }

                if session.infoScanned {
                    if let a = session.fidoInfo?.aaguidHex, let entry = mds.lookup(aaguid: a) {
                        Section {
                            DeviceHeaderCard(entry: entry)
                        }
                    }
                    Section("Applets") {
                        statusRow("OATH (TOTP/HOTP)", systemImage: "clock.fill", present: session.oathPresent)
                            .contentShape(Rectangle())
                            .onTapGesture { goToTab(1) }
                        if session.transportMode == .usb {
                            HStack {
                                Label("FIDO2 management", systemImage: "lock.shield.fill")
                                Spacer()
                                Text("NFC only").font(.caption).foregroundStyle(.secondary)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture { goToTab(2) }
                        } else {
                            statusRow("FIDO2 management", systemImage: "lock.shield.fill", present: session.fidoPresent)
                                .contentShape(Rectangle())
                                .onTapGesture { goToTab(2) }
                        }
                        statusRow("Token2 on-device OTP", systemImage: "key.horizontal.fill", present: session.token2Present)
                            .contentShape(Rectangle())
                            .onTapGesture { goToTab(1) }

                        // PIV — read-only status, tap for details.
                        appletDetailRow(
                            "PIV", systemImage: "person.text.rectangle.fill",
                            present: session.pivStatus != nil, absent: session.pivAbsent,
                            secondary: pivSecondary()) { showPiv = true }

                        // OpenPGP — read-only status, tap for details.
                        appletDetailRow(
                            "OpenPGP", systemImage: "envelope.fill",
                            present: session.pgpStatus != nil, absent: session.pgpAbsent,
                            secondary: pgpSecondary()) { showPgp = true }
                    }
                }

                Section("Transport") {
                    Label("NFC — all applets", systemImage: "wave.3.right")
                        .foregroundStyle(.secondary)
                    Label("USB-C — OATH, Token2 OTP, PIV, OpenPGP", systemImage: "cable.connector")
                        .foregroundStyle(.secondary)
                    Label("FIDO2 management — NFC only", systemImage: "lock.shield")
                        .foregroundStyle(.secondary)
                }

                Section {
                    HStack {
                        Text("Entries").foregroundStyle(.secondary)
                        Spacer()
                        Text("\(mds.entryCount)").monospacedDigit()
                    }
                    HStack {
                        Text("Source").foregroundStyle(.secondary)
                        Spacer()
                        Text(mds.sourceLabel.capitalized)
                    }
                    HStack {
                        Text("Updated").foregroundStyle(.secondary)
                        Spacer()
                        Text(mds.lastUpdated.map { relativeDate($0) } ?? "bundled")
                    }
                    if let err = mds.lastError {
                        Text(err).font(.footnote).foregroundStyle(.orange)
                    }
                    Button {
                        Task { await mds.updateFromFido() }
                    } label: {
                        if mds.isFetching {
                            HStack { ProgressView(); Text("Updating…") }
                        } else {
                            Label("Update from FIDO Alliance", systemImage: "arrow.down.circle")
                        }
                    }
                    .disabled(mds.isFetching)
                } header: {
                    Text("FIDO Metadata (MDS)")
                } footer: {
                    Text("Maps authenticator AAGUIDs to certified names. Fetches the live MDS3 blob from mds3.fidoalliance.org.")
                }

                Section {
                    Text("FIDO2 uses the key's CTAPHID interface, which iOS only exposes over NFC. All other applets work over NFC or USB-C.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Libre Key Companion")
            .onChange(of: session.usbCardReady) { ready in
                if ready && isActive {
                    Task { await session.scanInfo(); session.clearUSBReadyFlag() }
                }
            }
            .onChange(of: isActive) { active in
                if active && session.usbCardReady {
                    Task { await session.scanInfo(); session.clearUSBReadyFlag() }
                }
            }
            .sheet(isPresented: $showPiv) {
                if let s = session.pivStatus { PIVDetailView(status: s) }
            }
            .sheet(isPresented: $showPgp) {
                if let s = session.pgpStatus { OpenPGPDetailView(status: s) }
            }
        }
    }

    /// Jump to another tab (OTP=1, FIDO2=2) when an applet row is tapped.
    private func goToTab(_ index: Int) {
        selectedTab?.wrappedValue = index
    }

    private func relativeDate(_ date: Date) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f.localizedString(for: date, relativeTo: Date())
    }

    private func pivSecondary() -> String? {
        guard let s = session.pivStatus else { return session.pivAbsent ? "not on this key" : nil }
        let v = s.version.map { "v\($0)" } ?? ""
        return "\(v) · \(s.slotsWithCert.count) cert(s) · tap for details"
    }
    private func pgpSecondary() -> String? {
        guard let s = session.pgpStatus else { return session.pgpAbsent ? "not on this key" : nil }
        let n = s.keys.filter(\.present).count
        return "\(n)/3 keys · tap for details"
    }

    /// A present/absent row with a green check or a dimmed dash.
    @ViewBuilder
    private func statusRow(_ title: String, systemImage: String, present: Bool?) -> some View {
        HStack {
            Label(title, systemImage: systemImage)
            Spacer()
            if present == true {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            } else if present == false {
                Image(systemName: "minus.circle").foregroundStyle(.secondary)
            } else if session.infoBusy {
                ProgressView()
            } else {
                // Unknown and not currently scanning (e.g. the read was cancelled).
                Image(systemName: "questionmark.circle").foregroundStyle(.secondary)
            }
        }
    }

    /// A row for an applet with a tappable read-only detail popup.
    @ViewBuilder
    private func appletDetailRow(_ title: String, systemImage: String, present: Bool, absent: Bool,
                                 secondary: String?, action: @escaping () -> Void) -> some View {
        Button(action: present ? action : {}) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Label(title, systemImage: systemImage).foregroundStyle(.primary)
                    if let secondary {
                        Text(secondary).font(.caption).foregroundStyle(.secondary)
                            .padding(.leading, 28)
                    }
                }
                Spacer()
                if present {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                } else if absent {
                    Image(systemName: "minus.circle").foregroundStyle(.secondary)
                } else if session.infoBusy {
                    ProgressView()
                } else {
                    Image(systemName: "questionmark.circle").foregroundStyle(.secondary)
                }
            }
        }
        .disabled(!present)
        .foregroundStyle(.primary)
    }
}

/// Read-only PIV detail popup — version, GUID, retries, per-slot certificate info.
private struct PIVDetailView: View {
    let status: PIVApplet.PIVStatus
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section("Applet") {
                    detail("Version", status.version ?? "unknown")
                    if let g = status.cardGuidHex { detail("Card GUID", formatGuid(g)) }
                    detail("PIN retries", status.pinRetries.map { "\($0) left" } ?? "—")
                    detail("PUK retries", status.pukRetries.map { "\($0) left" } ?? "—")
                }
                if status.certs.isEmpty {
                    Section {
                        Text(status.slotsWithCert.isEmpty ? "No certificates in any slot."
                             : "Slots with data: \(status.slotsWithCert.joined(separator: ", "))")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                } else {
                    ForEach(status.certs.indices, id: \.self) { i in
                        let c = status.certs[i]
                        Section(c.slot) {
                            if let s = c.info.subjectSummary { detail("Subject", s) }
                            detail("SHA-256", c.info.sha256Fingerprint)
                        }
                    }
                }
            }
            .navigationTitle("PIV details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Close") { dismiss() } } }
        }
    }

    @ViewBuilder private func detail(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(k).font(.caption).foregroundStyle(.secondary)
            Text(v).font(.body).textSelection(.enabled)
        }
    }
    private func formatGuid(_ hex: String) -> String {
        guard hex.count == 32 else { return hex }
        let a = Array(hex)
        func s(_ r: Range<Int>) -> String { String(a[r]) }
        return "\(s(0..<8))-\(s(8..<12))-\(s(12..<16))-\(s(16..<20))-\(s(20..<32))"
    }
}

/// Read-only OpenPGP detail popup — spec, serial, cardholder, URL, retries, keys.
private struct OpenPGPDetailView: View {
    let status: OpenPGPApplet.CardStatus
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section("Card") {
                    detail("Spec", status.specVersion)
                    if let s = status.serialHex { detail("Serial", s) }
                    if let n = status.cardholderName { detail("Cardholder", n) }
                    if let u = status.url, !u.isEmpty { detail("URL", u) }
                    detail("PIN (PW1)", status.pin1Retries.map { "\($0) left" } ?? "—")
                    detail("Admin (PW3)", status.pin3Retries.map { "\($0) left" } ?? "—")
                }
                ForEach(status.keys.indices, id: \.self) { i in
                    let k = status.keys[i]
                    Section(k.name) {
                        if !k.present {
                            Text("(no key)").foregroundStyle(.secondary)
                        } else {
                            if let a = k.algorithm { detail("Algorithm", a) }
                            if let g = k.generated { detail("Generated", g) }
                            if let f = k.fingerprint { detail("Fingerprint", f.chunked(4)) }
                        }
                    }
                }
            }
            .navigationTitle("OpenPGP details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Close") { dismiss() } } }
        }
    }

    @ViewBuilder private func detail(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(k).font(.caption).foregroundStyle(.secondary)
            Text(v).font(.body).textSelection(.enabled)
        }
    }
}

private extension String {
    /// Group into space-separated chunks of n (for fingerprint readability).
    func chunked(_ n: Int) -> String {
        var out: [String] = []; var cur = ""
        for ch in self { cur.append(ch); if cur.count == n { out.append(cur); cur = "" } }
        if !cur.isEmpty { out.append(cur) }
        return out.joined(separator: " ")
    }
}
