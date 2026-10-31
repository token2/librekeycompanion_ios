# Token2USBFido

FIDO2 management over USB-C on iOS for Token2 keys. Part of Libre Key Companion
(linked as a local Swift package), so USB-C FIDO2 works in both the App Store and
open-source builds.

The FIDO applet isn't selectable on a Token2 key's USB smart-card (CCID)
interface, and iOS gives apps no CTAPHID access, so the standard CTAP binding is
unreachable over USB on iOS. Token2 keys accept CTAP2 tunnelled through the Token2
OTP applet instead; this package implements that tunnel and nothing else. All CTAP
logic (PIN protocols, credential management, bio enrollment, config) stays in the
app's open-source `Ctap2Client`.

## What's in here

| Item | Value |
|---|---|
| Applet | Token2 OTP, AID `F0 00 00 01 4F 74 70 01` (SELECT answers `1000`) |
| CTAP tunnel | `80 C5 03 00`, body = CTAP command byte + CBOR, response = CTAP status + CBOR |
| Alphanumeric min PIN | `80 C5 02 0A`, body = authenticatorConfig `0x0D` + CBOR (setMinPINLength), PIN/UV auth protocol 1 |
| Gating | slot name contains `TOKEN2` → OTP applet SELECT `9000` → tunnelled getInfo returns status `00` + CBOR map |

Verified on R3.4 hardware (22 Oct 2026, Windows/pyscard): tunnel getInfo returns
a 355-byte CBOR map with or without an OTP password set; the FIDO AID answers
`6A81` on CCID. USB VID/PID isn't visible to iOS apps, hence the slot-name
pre-filter plus the applet checks. The `(00xx)` suffix in the slot name varies by
key, so it isn't used.

## How it's linked

This package lives in the app repo and is referenced as a **local Swift package**
(`XCLocalSwiftPackageReference "Token2USBFido"` in `LibreKeyCompanion.xcodeproj`),
added to the `LibreKeyCompanion` target. Because it's always present,
`#if canImport(Token2USBFido)` (in `Token2UsbFidoProvider.swift`) is true for every
build, and `UsbFido.registerBuiltIns()` registers the provider at launch — so
USB-C FIDO2 works in both the App Store and open-source builds.

If the project ever loses the reference (e.g. after a `.pbxproj` reset), re-link it:

```sh
gem install xcodeproj        # if not installed
ruby Token2USBFido/scripts/link-into-app.rb ./Token2USBFido
```

Or in Xcode: File ▸ Add Package Dependencies ▸ Add Local… ▸ select the
`Token2USBFido` folder ▸ add the `Token2USBFido` library to the LibreKeyCompanion
target.

To confirm it's active: with a Token2 R3.4 key plugged in over USB-C, the FIDO2 tab
shows **Connection: USB-C**.

## Tests

`swift test` (macOS) runs the wire-level tests against the captured APDUs.
