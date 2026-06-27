import SwiftUI

/// NFC/USB transport selector. Only meaningful when a USB smart-card key is
/// attached; otherwise the app uses NFC. FIDO2 is unaffected (always NFC).
struct TransportPicker: View {
    @EnvironmentObject var session: KeySession

    var body: some View {
        if session.usbAvailable {
            Picker("Connection", selection: $session.transportMode) {
                Label("NFC", systemImage: "wave.3.right").tag(KeySession.TransportMode.nfc)
                Label("USB", systemImage: "cable.connector").tag(KeySession.TransportMode.usb)
            }
            .pickerStyle(.segmented)
        }
    }
}
