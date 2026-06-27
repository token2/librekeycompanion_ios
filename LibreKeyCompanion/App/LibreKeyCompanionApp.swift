import SwiftUI

@main
struct LibreKeyCompanionApp: App {
    @StateObject private var session = KeySession()
    @StateObject private var mds = MDSRepository()

    var body: some Scene {
        WindowGroup {
            RootTabView()
                .environmentObject(session)
                .environmentObject(mds)
        }
    }
}
