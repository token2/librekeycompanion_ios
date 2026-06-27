import Foundation
#if canImport(CryptoTokenKit)
import CryptoTokenKit
#endif

/// Watches for USB smart-card attachment/removal and a card becoming readable,
/// so the app can auto-read on plug-in instead of requiring a button tap.
///
/// CryptoTokenKit doesn't push notifications, so this polls the slot manager on a
/// timer (cheap: just reading `slotNames` and each slot's `state`). When a slot
/// transitions into a present/valid-card state, `onCardReady` fires once.
@MainActor
final class USBMonitor: ObservableObject {
    /// True when at least one USB smart-card slot is attached.
    @Published private(set) var attached = false
    /// True when a slot currently holds a readable card.
    @Published private(set) var cardReady = false

    /// Called once each time a card becomes ready (rising edge), so the owner can
    /// trigger an automatic read.
    var onCardReady: (() -> Void)?
    /// Called when the attached state changes (key plugged in / unplugged).
    var onAttachChange: ((Bool) -> Void)?

    private var timer: Timer?
    private var lastCardReady = false
    private var lastAttached = false

    func start() {
        #if canImport(CryptoTokenKit)
        guard TKSmartCardSlotManager.default != nil else { return }
        // Poll ~2x/sec. Light enough to leave running while the relevant tabs are up.
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
        poll()
        #endif
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    private func poll() {
        #if canImport(CryptoTokenKit)
        guard let manager = TKSmartCardSlotManager.default else {
            if lastAttached { onAttachChange?(false); lastAttached = false }
            set(attached: false, cardReady: false); return
        }
        let names = manager.slotNames
        let nowAttached = !names.isEmpty
        if nowAttached != lastAttached {
            attached = nowAttached
            onAttachChange?(nowAttached)
            lastAttached = nowAttached
        } else {
            attached = nowAttached
        }

        // A card is "ready" if any attached slot reports a valid card. Slot lookup
        // is async; we use the already-resolved slot if available, else trigger a
        // resolve and judge on the next poll.
        var anyReady = false
        for name in names {
            if let slot = resolvedSlots[name] {
                if slot.state == .validCard { anyReady = true }
            } else {
                manager.getSlot(withName: name) { [weak self] slot in
                    Task { @MainActor in if let slot { self?.resolvedSlots[name] = slot } }
                }
            }
        }
        // Drop slots that detached.
        resolvedSlots = resolvedSlots.filter { names.contains($0.key) }

        let nowReady = anyReady
        cardReady = nowReady
        if nowReady && !lastCardReady {
            onCardReady?()        // rising edge — fire the auto-read
        }
        lastCardReady = nowReady
        #endif
    }

    private func set(attached a: Bool, cardReady c: Bool) {
        attached = a; cardReady = c; lastCardReady = c
    }

    #if canImport(CryptoTokenKit)
    private var resolvedSlots: [String: TKSmartCardSlot] = [:]
    #endif
}
