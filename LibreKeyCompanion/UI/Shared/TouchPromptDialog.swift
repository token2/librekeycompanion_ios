import SwiftUI

/// A centered, auto-dismissing dialog shown while the app waits for a physical
/// button press on the key (e.g. revealing a touch-required code over USB, where
/// there's no system NFC sheet to convey "touch your key"). It appears while
/// `KeySession.touchPrompt` is non-nil and fades out when the read completes.
struct TouchPromptDialog: View {
    let message: String

    @State private var pulse = false

    var body: some View {
        ZStack {
            // Dim backdrop.
            Color.black.opacity(0.35)
                .ignoresSafeArea()

            VStack(spacing: 16) {
                Image(systemName: "hand.tap.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(.orange)
                    .scaleEffect(pulse ? 1.12 : 0.92)
                    .animation(.easeInOut(duration: 0.7).repeatForever(autoreverses: true), value: pulse)
                Text("Confirm on your key")
                    .font(.headline)
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(28)
            .frame(maxWidth: 300)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .shadow(radius: 20)
        }
        .transition(.opacity)
        .onAppear { pulse = true }
    }
}
