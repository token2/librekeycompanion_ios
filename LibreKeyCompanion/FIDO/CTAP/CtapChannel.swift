import Foundation

/// How CTAP2 commands reach the authenticator.
///
/// The open-source build only ships `StandardCtapChannel`: the ISO 7816 CTAP
/// binding (`80 10 00 00` on the FIDO AID), which is what NFC uses. Other
/// channels can be supplied at runtime through `UsbFido.provider` — for example a
/// vendor channel that carries CTAP over a key's USB smart-card interface. Nothing
/// above this protocol needs to know which channel is in use.
protocol CtapChannel: AnyObject {
    /// Activate whatever applet the channel talks through. Called once per
    /// operation, before the first command.
    func select() async throws

    /// Send one CTAP2 command (command byte + CBOR parameters). Returns the raw
    /// CTAP response body: status byte followed by the CBOR payload.
    func send(command: Int, data: Data) async throws -> Data

    /// True when the underlying session stays open while the user interacts with
    /// the key (USB), so multi-touch flows such as fingerprint enrollment work.
    /// NFC sessions are short and the key may lose power between touches.
    var holdsSession: Bool { get }

    /// True when the channel can set a separate minimum length for PINs that
    /// contain letters or symbols (a vendor extension; not part of CTAP).
    var supportsAlphanumericMinPin: Bool { get }

    /// Send an authenticatorConfig body (command byte + CBOR) that applies to the
    /// alphanumeric minimum PIN length. Only called when
    /// `supportsAlphanumericMinPin` is true. PIN/UV auth protocol 1 is used.
    func sendAlphanumericMinPinConfig(data: Data) async throws -> Data
}

extension CtapChannel {
    var holdsSession: Bool { false }
    var supportsAlphanumericMinPin: Bool { false }
    func sendAlphanumericMinPinConfig(data: Data) async throws -> Data {
        throw KeyError.unsupportedOnPlatform("This key doesn't support a separate alphanumeric PIN minimum.")
    }
}

/// The ISO 7816 CTAP binding: SELECT the FIDO AID, then `80 10 00 00` with the
/// CTAP command byte + CBOR as the body. Works over NFC on every FIDO2 key.
final class StandardCtapChannel: CtapChannel {
    static let fidoAid = Data([0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])

    private let transport: KeyTransport
    let holdsSession: Bool

    init(transport: KeyTransport) {
        self.transport = transport
        self.holdsSession = transport is CCIDTransport
    }

    func select() async throws {
        try await transport.selectApplet(aid: StandardCtapChannel.fidoAid)
    }

    func send(command: Int, data: Data) async throws -> Data {
        var payload = Data([UInt8(command)]); payload.append(data)
        let r = try await transport.transmit(APDU(cla: 0x80, ins: 0x10, p1: 0x00, p2: 0x00, data: payload, le: 256))
        guard r.isSuccess else { throw CtapError(code: 0xFF) }
        return r.data
    }
}

/// Supplies a CTAP channel for a key attached over USB (CryptoTokenKit), where
/// the standard binding isn't reachable because the FIDO applet is only exposed
/// on the key's HID interface.
protocol UsbFidoProvider: AnyObject {
    /// Return a channel if this provider recognises and supports the attached
    /// key, or nil to leave FIDO2 on NFC. `slotName` is the CryptoTokenKit slot
    /// (reader) name. The provider may exchange APDUs to identify the key; the
    /// transport is already connected and stays owned by the caller.
    func channel(for transport: KeyTransport, slotName: String?) async -> CtapChannel?
}

/// Registry for the optional USB FIDO2 provider. Empty in the open-source
/// build, so FIDO2 stays NFC-only there.
enum UsbFido {
    static var provider: UsbFidoProvider?

    /// Called once at launch. Registers any provider compiled into this build.
    static func registerBuiltIns() {
        #if canImport(Token2USBFido)
        provider = Token2UsbFidoProvider()
        #endif
    }
}
