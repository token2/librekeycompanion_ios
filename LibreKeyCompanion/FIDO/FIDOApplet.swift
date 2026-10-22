import Foundation

/// FIDO2 / CTAP2 *management* over a `CtapChannel`.
///
/// Thin wrapper over `Ctap2Client`. By default the channel is the standard ISO
/// 7816 CTAP binding (NFC). A build may register a `UsbFidoProvider` that
/// supplies a channel for keys plugged in over USB-C; everything here works the
/// same over either. Fingerprint capture needs `holdsSession` (USB).
final class FIDOApplet {
    let client: Ctap2Client
    init(transport: KeyTransport) { self.client = Ctap2Client(transport: transport) }
    init(channel: CtapChannel) { self.client = Ctap2Client(channel: channel) }

    var holdsSession: Bool { client.channel.holdsSession }
    var supportsAlphanumericMinPin: Bool { client.channel.supportsAlphanumericMinPin }

    func getInfo() async throws -> Ctap2Client.Info { try await client.getInfo() }
    func getPinRetries() async throws -> Int { try await client.getPinRetries() }
    func setPin(_ newPin: String) async throws {
        let info = try await client.getInfo()
        try await client.setPin(newPin, info: info)
    }
    func changePin(old: String, new: String) async throws {
        let info = try await client.getInfo()
        try await client.changePin(old: old, new: new, info: info)
    }
    func toggleAlwaysUv(pin: String) async throws {
        try await client.toggleAlwaysUv(pin: pin)
    }
    func setMinPinLength(pin: String, length: Int, alphanumeric: Bool) async throws {
        try await client.setMinPinLength(pin: pin, length: length, alphanumeric: alphanumeric)
    }
    func reset() async throws { try await client.reset() }
    func listPasskeys(pin: String) async throws -> [Ctap2Client.Passkey] {
        try await client.listPasskeys(pin: pin)
    }
    func deletePasskey(pin: String, credentialId: Data) async throws {
        try await client.deletePasskey(pin: pin, credentialId: credentialId)
    }
    func bioSession(pin: String) async throws -> Ctap2Client.BioSession {
        try await client.bioSession(pin: pin)
    }
}
