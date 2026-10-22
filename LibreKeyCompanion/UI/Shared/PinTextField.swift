import SwiftUI
import UIKit

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

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

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
        tf.setContentHuggingPriority(.defaultLow, for: .horizontal)
        tf.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return tf
    }

    func updateUIView(_ tf: FocusingTextField, context: Context) {
        context.coordinator.text = $text
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
        init(text: Binding<String>) { self.text = text }
        @objc func changed(_ tf: UITextField) { text.wrappedValue = tf.text ?? "" }
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
