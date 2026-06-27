import SwiftUI

/// Editable fields for a new OTP entry, matching the Android AddEntryDialog: a QR
/// scan or pasted otpauth URI POPULATES these fields so the user can review and
/// adjust before writing. Settings: issuer/app, account, Base32 secret, algorithm
/// (SHA1/SHA256), period (30/60), digits, and (for keys that support it) require-touch.
struct OTPEntryFields {
    var uri: String = ""
    var app: String = ""
    var account: String = ""
    var secret: String = ""
    var algorithm: OATHAlgorithm = .sha1
    var period: Int = 30
    var digits: Int = 6
    var requireTouch: Bool = false
    var isHotp: Bool = false

    /// Parse an otpauth URI and fill the fields (mirrors Android's parseOtpauth,
    /// including the SHA256 fallback that scans the whole payload).
    mutating func applyScannedUri(_ raw: String) {
        uri = raw
        guard let p = OTPAuthURI(raw) else { return }
        app = p.issuerForToken2
        account = p.accountForToken2
        // Re-extract the Base32 secret string from the URI for display/edit.
        if let comps = URLComponents(string: raw),
           let s = comps.queryItems?.first(where: { $0.name == "secret" })?.value {
            secret = s
        }
        // SHA256: trust the parsed algorithm, but also honor a payload that bakes
        // "sha256" into a label (vendor QRs) even without an algorithm= param.
        if p.algorithm == .sha256 || raw.lowercased().contains("sha256") {
            algorithm = .sha256
        } else if p.algorithm == .sha512 {
            algorithm = .sha512
        } else {
            algorithm = .sha1
        }
        period = p.period
        digits = p.digits
        isHotp = p.kind == .hotp
    }

    /// Validate and build a Token2 entry from the (possibly edited) fields.
    func buildToken2Entry() -> Token2Codec.Entry? {
        let acct = account.trimmingCharacters(in: .whitespaces)
        let appName = app.trimmingCharacters(in: .whitespaces)
        guard !acct.isEmpty, let seed = Base32.decode(secret), !seed.isEmpty else { return nil }
        let entry = Token2Codec.Entry(
            type: isHotp ? Token2Codec.TYPE_HOTP : Token2Codec.TYPE_TOTP,
            algorithm: algorithm == .sha256 ? Token2Codec.ALG_SHA256 : Token2Codec.ALG_SHA1,
            timestep: period,
            codeLength: digits,
            buttonRequired: requireTouch,
            appName: appName,
            accountName: acct,
            seed: seed)
        // §9 bounds.
        guard (1...64).contains(Data(acct.utf8).count),
              (0...64).contains(Data(appName.utf8).count),
              (1...64).contains(seed.count),
              (4...10).contains(digits),
              (1...0xFFFF).contains(period) else { return nil }
        return entry
    }

    /// Reconstruct an otpauth URI for the YKOATH path (which consumes a URI).
    func buildOtpauthUri() -> String? {
        guard !account.isEmpty, Base32.decode(secret) != nil else { return nil }
        let type = isHotp ? "hotp" : "totp"
        let label = app.isEmpty ? account : "\(app):\(account)"
        var comps = URLComponents()
        comps.scheme = "otpauth"
        comps.host = type
        comps.path = "/" + label
        var items = [URLQueryItem(name: "secret", value: secret)]
        if !app.isEmpty { items.append(URLQueryItem(name: "issuer", value: app)) }
        items.append(URLQueryItem(name: "algorithm", value: algorithm.rawValue))
        items.append(URLQueryItem(name: "digits", value: String(digits)))
        items.append(URLQueryItem(name: "period", value: String(period)))
        comps.queryItems = items
        return comps.string
    }
}

/// Full manual-entry form. QR scan fills the same fields for review/edit.
struct AddEntryForm: View {
    @Binding var fields: OTPEntryFields
    @Environment(\.dismiss) private var dismiss
    @State private var showScanner = false
    @State private var scanError: String?
    let onAdd: (OTPEntryFields) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Button {
                        scanError = nil; showScanner = true
                    } label: {
                        Label("Scan QR code", systemImage: "qrcode.viewfinder")
                    }
                    if let scanError {
                        Text(scanError).font(.footnote).foregroundStyle(.orange)
                    }
                } footer: {
                    Text("Scanning fills the fields below so you can review and edit before saving.")
                }

                Section("Account") {
                    TextField("Issuer / app (optional)", text: $fields.app)
                        .autocorrectionDisabled()
                    TextField("Account name", text: $fields.account)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section("Secret") {
                    TextField("Base32 secret", text: $fields.secret, axis: .vertical)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                        .font(.system(.body, design: .monospaced))
                }

                Section("Settings") {
                    Picker("Algorithm", selection: $fields.algorithm) {
                        Text("SHA1").tag(OATHAlgorithm.sha1)
                        Text("SHA256").tag(OATHAlgorithm.sha256)
                    }
                    Picker("Period", selection: $fields.period) {
                        Text("30s").tag(30)
                        Text("60s").tag(60)
                    }
                    Stepper("Digits: \(fields.digits)", value: $fields.digits, in: 4...10)
                    Toggle("Require touch", isOn: $fields.requireTouch)
                }
            }
            .navigationTitle("Add OTP entry")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") { onAdd(fields); dismiss() }
                        .disabled(fields.account.isEmpty || fields.secret.isEmpty)
                }
            }
            .sheet(isPresented: $showScanner) {
                #if canImport(AVFoundation) && canImport(UIKit)
                NavigationStack {
                    QRScannerView(
                        onScan: { value in fields.applyScannedUri(value); showScanner = false },
                        onError: { msg in scanError = msg; showScanner = false })
                    .ignoresSafeArea()
                    .navigationTitle("Scan QR")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { showScanner = false }
                        }
                    }
                }
                #else
                Text("QR scanning requires a physical device.")
                #endif
            }
        }
    }
}
