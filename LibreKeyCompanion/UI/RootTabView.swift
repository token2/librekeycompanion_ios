import SwiftUI

/// Three-tab shell mirroring the Android app's Info / OTP / FIDO2 screens.
struct RootTabView: View {
    @EnvironmentObject var session: KeySession
    @State private var selectedTab = 0
    @State private var oathPassword = ""

    /// Drives the OATH password alert. Dismissing it any way other than
    /// submitting cancels the pending operation.
    private var passwordAlertBinding: Binding<Bool> {
        Binding(get: { session.oathPasswordRequest != nil },
                set: { shown in
                    if !shown, session.oathPasswordRequest != nil {
                        oathPassword = ""
                        session.cancelOATHPassword()
                    }
                })
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            InfoView(isActive: selectedTab == 0, selectedTab: $selectedTab)
                .tabItem { Label("Info", systemImage: "key.fill") }
                .tag(0)
            OTPView(isActive: selectedTab == 1)
                .tabItem { Label("OTP", systemImage: "clock.fill") }
                .tag(1)
            FIDOView()
                .tabItem { Label("FIDO2", systemImage: "lock.shield.fill") }
                .tag(2)
        }
        .onAppear { session.startUSBMonitoring() }
        .onDisappear { session.stopUSBMonitoring() }
        // Presented from whichever tab hit the lock — Info and OTP both read OATH.
        .alert(session.oathPasswordRequest?.wrongPassword == true
                   ? "Wrong password" : "OATH password required",
               isPresented: passwordAlertBinding,
               presenting: session.oathPasswordRequest) { _ in
            SecureField("Password", text: $oathPassword)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Unlock") {
                let entered = oathPassword
                oathPassword = ""
                guard !entered.isEmpty else { session.cancelOATHPassword(); return }
                session.submitOATHPassword(entered)
            }
            Button("Cancel", role: .cancel) {
                oathPassword = ""
                session.cancelOATHPassword()
            }
        } message: { request in
            Text(request.wrongPassword
                 ? "The key rejected that password. This is not a PIN — a wrong attempt uses up no retries. Enter it again, then hold the key to the phone."
                 : "This key's OATH accounts are protected by a password. Enter it, then hold the key to the phone again. It is kept only for this session.")
        }
    }
}
