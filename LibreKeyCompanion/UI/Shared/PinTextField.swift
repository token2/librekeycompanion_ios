import SwiftUI
import UIKit
import GameController

/// Secure PIN/password field backed by `UITextField`.
///
/// SwiftUI's `SecureField` + `@FocusState` is unreliable in sheets: focus set
/// during the presentation animation, or right after the field is rebuilt, can
/// leave the field focused with no keyboard on screen. This field asks UIKit for
/// first-responder status directly once it's in a window, and switches between
/// the number pad and the full keyboard in place (`reloadInputViews`), so the
/// keyboard always follows focus.
struct PinTextField: UIViewRepresentable {
    let placeholder: String
    @Binding var text: String
    /// Full keyboard (letters & symbols) instead of the number pad.
    var alphanumeric: Bool = false
    /// Take focus and raise the keyboard as soon as the field appears.
    var autoFocus: Bool = false
    /// Mirrors first-responder status.
    var isFocused: Binding<Bool>? = nil

    func makeCoordinator() -> Coordinator { Coordinator(text: $text, isFocused: isFocused) }

    func makeUIView(context: Context) -> FocusingTextField {
        let tf = FocusingTextField()
        tf.isSecureTextEntry = true
        tf.placeholder = placeholder
        tf.autocorrectionType = .no
        tf.autocapitalizationType = .none
        tf.spellCheckingType = .no
        tf.smartQuotesType = .no
        tf.smartDashesType = .no
        tf.keyboardType = alphanumeric ? .asciiCapable : .numberPad
        tf.text = text
        tf.wantsFocusOnAppear = autoFocus
        tf.addTarget(context.coordinator, action: #selector(Coordinator.changed(_:)), for: .editingChanged)
        tf.addTarget(context.coordinator, action: #selector(Coordinator.began(_:)), for: .editingDidBegin)
        tf.addTarget(context.coordinator, action: #selector(Coordinator.ended(_:)), for: .editingDidEnd)
        tf.setContentHuggingPriority(.defaultLow, for: .horizontal)
        tf.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return tf
    }

    func updateUIView(_ tf: FocusingTextField, context: Context) {
        context.coordinator.text = $text
        context.coordinator.isFocused = isFocused
        if tf.text != text { tf.text = text }
        let kb: UIKeyboardType = alphanumeric ? .asciiCapable : .numberPad
        if tf.keyboardType != kb {
            tf.keyboardType = kb
            // Switching keypads means the user wants to type: keep (or bring
            // back) the keyboard, now in the new layout.
            if tf.isFirstResponder { tf.reloadInputViews() } else { tf.focusSoon() }
        }
    }

    final class Coordinator: NSObject {
        var text: Binding<String>
        var isFocused: Binding<Bool>?
        init(text: Binding<String>, isFocused: Binding<Bool>?) { self.text = text; self.isFocused = isFocused }
        @objc func changed(_ tf: UITextField) { text.wrappedValue = tf.text ?? "" }
        @objc func began(_ tf: UITextField) { isFocused?.wrappedValue = true }
        @objc func ended(_ tf: UITextField) { isFocused?.wrappedValue = false }
    }
}

final class FocusingTextField: UITextField {
    var wantsFocusOnAppear = false

    override func didMoveToWindow() {
        super.didMoveToWindow()
        guard wantsFocusOnAppear, window != nil else { return }
        wantsFocusOnAppear = false
        focusSoon()
    }

    /// becomeFirstResponder is ignored while a sheet is still animating in, so
    /// retry briefly until it takes.
    func focusSoon(attempt: Int = 0) {
        DispatchQueue.main.asyncAfter(deadline: .now() + (attempt == 0 ? 0.3 : 0.2)) { [weak self] in
            guard let self, self.window != nil, !self.isFirstResponder else { return }
            if !self.becomeFirstResponder(), attempt < 5 { self.focusSoon(attempt: attempt + 1) }
        }
    }
}

/// Tracks whether iOS sees a hardware keyboard. A security key with its
/// HID-HOTP (keyboard) channel enabled counts as one while it's plugged in, and
/// iOS then hides the on-screen keyboard for every text field.
final class HardwareKeyboardMonitor: ObservableObject {
    static let shared = HardwareKeyboardMonitor()
    @Published private(set) var connected: Bool

    private init() {
        connected = GCKeyboard.coalesced != nil
        let nc = NotificationCenter.default
        nc.addObserver(forName: .GCKeyboardDidConnect, object: nil, queue: .main) { [weak self] _ in
            self?.connected = true
        }
        nc.addObserver(forName: .GCKeyboardDidDisconnect, object: nil, queue: .main) { [weak self] _ in
            self?.connected = GCKeyboard.coalesced != nil
        }
    }
}

/// PIN entry used by every PIN sheet: the secure field plus an in-app number
/// pad. The pad opens by itself when iOS is suppressing its own keyboard
/// because a hardware keyboard is attached (typically the plugged-in key's
/// HID-HOTP channel), and can be opened manually with the keypad button.
struct PinEntryField: View {
    let placeholder: String
    @Binding var text: String
    var alphanumeric: Bool = false
    var autoFocus: Bool = false

    @ObservedObject private var hw = HardwareKeyboardMonitor.shared
    @State private var focused = false
    @State private var manualPad = false

    private var showPad: Bool { focused && (hw.connected || manualPad) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                PinTextField(placeholder: placeholder, text: $text, alphanumeric: alphanumeric,
                             autoFocus: autoFocus, isFocused: $focused)
                Button {
                    manualPad.toggle()
                } label: {
                    Image(systemName: "circle.grid.3x3").accessibilityLabel("Number pad")
                }
                .buttonStyle(.borderless)
            }
            if showPad {
                PinKeypad(text: $text)
                if hw.connected {
                    Text(alphanumeric
                         ? "iOS hides its keyboard while a keyboard device is attached — usually the plugged-in key's HID-HOTP channel. Letters can't be typed here; turn HID-HOTP off in Info ▸ USB channels, or unplug the key and use NFC."
                         : "iOS hides its keyboard while a keyboard device is attached — usually the plugged-in key's HID-HOTP channel. Use this pad, or turn HID-HOTP off in Info ▸ USB channels.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// Plain 0–9 pad that edits a bound string.
struct PinKeypad: View {
    @Binding var text: String
    private let rows: [[String]] = [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["", "0", "⌫"]]

    var body: some View {
        VStack(spacing: 8) {
            ForEach(rows, id: \.self) { row in
                HStack(spacing: 8) {
                    ForEach(row, id: \.self) { key in
                        if key.isEmpty {
                            Color.clear.frame(maxWidth: .infinity, minHeight: 44)
                        } else {
                            Button {
                                tap(key)
                            } label: {
                                Text(key)
                                    .font(.title3.weight(.medium))
                                    .frame(maxWidth: .infinity, minHeight: 44)
                                    .background(Color(uiColor: .tertiarySystemFill), in: RoundedRectangle(cornerRadius: 8))
                            }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.primary)
                        }
                    }
                }
            }
        }
    }

    private func tap(_ key: String) {
        if key == "⌫" { if !text.isEmpty { text.removeLast() } }
        else if text.count < 63 { text.append(key) }
    }
}
