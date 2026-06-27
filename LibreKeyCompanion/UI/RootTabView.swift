import SwiftUI

/// Three-tab shell mirroring the Android app's Info / OTP / FIDO2 screens.
struct RootTabView: View {
    @EnvironmentObject var session: KeySession
    @State private var selectedTab = 0
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
    }
}
