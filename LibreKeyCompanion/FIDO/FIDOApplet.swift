import Foundation

/// FIDO2 / CTAP2 *management* over NFC APDUs.
///
/// Thin wrapper over `Ctap2Client` (the NFC ApduWire path). On iOS, FIDO2 is
/// reachable only via the CTAP-over-NFC APDU binding — there is no CTAPHID/USB.
/// Scope: getInfo, PIN retries, set/change PIN, list/delete passkeys. Fingerprint
/// enrollment is intentionally out of scope (needs a held multi-touch session).
final class FIDOApplet {
    private let client: Ctap2Client
    init(transport: KeyTransport) { self.client = Ctap2Client(transport: transport) }

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
    func listPasskeys(pin: String) async throws -> [Ctap2Client.Passkey] {
        try await client.listPasskeys(pin: pin)
    }
    func deletePasskey(pin: String, credentialId: Data) async throws {
        try await client.deletePasskey(pin: pin, credentialId: credentialId)
    }
}
