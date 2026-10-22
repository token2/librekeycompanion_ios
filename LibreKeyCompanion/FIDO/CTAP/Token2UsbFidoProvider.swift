#if canImport(Token2USBFido)
import Foundation
import Token2USBFido

/// Adapter between the app's CTAP layer and the Token2USBFido package. Only
/// compiled when that package is linked (App Store builds); the open-source
/// build leaves `UsbFido.provider` empty and keeps FIDO2 on NFC.
final class Token2UsbFidoProvider: UsbFidoProvider {
    func channel(for transport: KeyTransport, slotName: String?) async -> CtapChannel? {
        guard Token2USBFido.isCandidateSlot(slotName) else { return nil }
        let link = Token2USBFido(exchange: Self.exchange(over: transport))
        guard await link.identify() else { return nil }
        return Token2UsbCtapChannel(link: link)
    }

    static func exchange(over transport: KeyTransport) -> Token2USBFido.Exchange {
        { [weak transport] cla, ins, p1, p2, data in
            guard let transport else { throw KeyError.notConnected }
            let r = try await transport.transmit(APDU(cla: cla, ins: ins, p1: p1, p2: p2, data: data, le: 256))
            return (data: r.data, sw: r.sw)
        }
    }
}

private final class Token2UsbCtapChannel: CtapChannel {
    private let link: Token2USBFido
    init(link: Token2USBFido) { self.link = link }

    var holdsSession: Bool { true }
    var supportsAlphanumericMinPin: Bool { true }

    func select() async throws {
        do { try await link.open() } catch { throw Self.map(error) }
    }

    func send(command: Int, data: Data) async throws -> Data {
        do { return try await link.ctap(command: UInt8(command), cbor: data) } catch { throw Self.map(error) }
    }

    func sendAlphanumericMinPinConfig(data: Data) async throws -> Data {
        do { return try await link.alphanumericMinPinConfig(body: data) } catch { throw Self.map(error) }
    }

    private static func map(_ error: Error) -> Error {
        if let e = error as? Token2USBFido.LinkError, case .status(let sw) = e {
            return KeyError.unexpectedStatus(sw)
        }
        return error
    }
}
#endif
