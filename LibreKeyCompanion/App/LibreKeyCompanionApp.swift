import SwiftUI

@main
struct LibreKeyCompanionApp: App {
    @StateObject private var session = KeySession()
    @StateObject private var mds = MDSRepository()

    init() { UsbFido.registerBuiltIns() }

    var body: some Scene {
        WindowGroup {
            RootTabView()
                .environmentObject(session)
                .environmentObject(mds)
        }
    }
}
