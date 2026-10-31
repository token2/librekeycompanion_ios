import Foundation

/// FIDO2 management for Token2 keys over the USB smart-card (CCID) interface.
///
/// The FIDO applet isn't selectable on a Token2 key's CCID interface (SELECT
/// answers 6A81), so the standard ISO 7816 CTAP binding can't be used over USB.
/// Token2 keys instead accept CTAP2 commands tunnelled through the Token2 OTP
/// applet. Firmware R3.4 and later; independent of the OTP password lock.
///
/// The package is transport-agnostic: the host app supplies `Exchange`, which
/// sends one APDU (header + body, short Le) and returns the full response data
/// and status word, with any 61xx GET RESPONSE chaining already done.
///
/// Proprietary. Not part of the open-source Libre Key Companion.
public final class Token2USBFido {
    public typealias Exchange = (_ cla: UInt8, _ ins: UInt8, _ p1: UInt8, _ p2: UInt8, _ data: Data)
        async throws -> (data: Data, sw: UInt16)

    public enum LinkError: Error, Equatable {
        /// The key answered a tunnel APDU with a non-9000 status word.
        case status(UInt16)
        /// The tunnel answered 9000 with no CTAP status byte.
        case emptyResponse
    }

    // Token2 OTP applet, through which the tunnel runs.
    static let otpAid = Data([0xF0, 0x00, 0x00, 0x01, 0x4F, 0x74, 0x70, 0x01])
    static let cla: UInt8 = 0x80
    static let ins: UInt8 = 0xC5
    /// CTAP2 tunnel: body = CTAP command byte + CBOR; response = status + CBOR.
    static let tunnelP1P2: (UInt8, UInt8) = (0x03, 0x00)
    /// authenticatorConfig whose setMinPINLength applies to the alphanumeric
    /// minimum. Same body shape as the tunnel; PIN/UV auth protocol 1.
    static let alphaMinPinP1P2: (UInt8, UInt8) = (0x02, 0x0A)
    static let ctapGetInfo: UInt8 = 0x04

    private let exchange: Exchange

    public init(exchange: @escaping Exchange) { self.exchange = exchange }

    /// Cheap pre-filter on the CryptoTokenKit slot (reader) name. iOS doesn't
    /// expose USB VID/PID to apps; Token2 keys enumerate their CCID reader as
    /// "TOKEN2 …". The applet checks in `identify()` are what actually gate.
    public static func isCandidateSlot(_ slotName: String?) -> Bool {
        guard let slotName else { return false }
        return slotName.range(of: "TOKEN2", options: .caseInsensitive) != nil
    }

    /// Select the Token2 OTP applet. Call before a batch of tunnel commands.
    public func open() async throws {
        let r = try await exchange(0x00, 0xA4, 0x04, 0x00, Self.otpAid)
        guard r.sw == 0x9000 else { throw LinkError.status(r.sw) }
    }

    /// True when the attached key is a Token2 key whose firmware answers CTAP
    /// through the tunnel: the OTP applet selects and a tunnelled getInfo returns
    /// CTAP success with a CBOR map.
    public func identify() async -> Bool {
        do {
            try await open()
            let body = try await ctap(command: Self.ctapGetInfo, cbor: Data())
            guard body.count >= 2, body[body.startIndex] == 0x00 else { return false }
            let first = body[body.index(after: body.startIndex)]
            return (first & 0xE0) == 0xA0          // CBOR major type 5 (map)
        } catch {
            return false
        }
    }

    /// Send one CTAP2 command through the tunnel. Returns the raw CTAP response
    /// body (status byte + CBOR); CTAP-level errors are left to the caller.
    public func ctap(command: UInt8, cbor: Data) async throws -> Data {
        try await send(Self.tunnelP1P2, command: command, cbor: cbor)
    }

    /// Send an authenticatorConfig body (command byte + CBOR, as built for the
    /// standard binding) so that setMinPINLength applies to the alphanumeric
    /// minimum. Returns the raw CTAP response body.
    public func alphanumericMinPinConfig(body: Data) async throws -> Data {
        guard let command = body.first else { throw LinkError.emptyResponse }
        return try await send(Self.alphaMinPinP1P2, command: command, cbor: Data(body.dropFirst()))
    }

    private func send(_ p1p2: (UInt8, UInt8), command: UInt8, cbor: Data) async throws -> Data {
        var payload = Data([command]); payload.append(cbor)
        let r = try await exchange(Self.cla, Self.ins, p1p2.0, p1p2.1, payload)
        guard r.sw == 0x9000 else { throw LinkError.status(r.sw) }
        guard !r.data.isEmpty else { throw LinkError.emptyResponse }
        return r.data
    }
}
