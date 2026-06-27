# Libre Key Companion - iOS 
 


An iOS (SwiftUI) port of [token2/librekeycompanion](https://github.com/token2/librekeycompanion), <img align="right" src="https://raw.githubusercontent.com/token2/librekeycompanion/refs/heads/main/logo.svg"><br><br>
a manufacturer-agnostic manager for hardware security keys.



> **Scope:** This is the **NFC-reachable subset** of the original Android app.
> See *Platform constraints* below for why a 1:1 port is not possible on iOS (yet).





## Platform constraints (read this first)

The Android app talks to keys over **two** transports: NFC (ISO-DEP) and USB-C
(CCID for smart-card applets, CTAPHID for FIDO2). iOS only allows one of these
for third-party apps:

| Transport | Android | iOS | Reason |
|-----------|:-------:|:---:|--------|
| NFC ISO7816 APDUs | ✅ | ✅ | CoreNFC `NFCISO7816Tag` exposes raw APDU exchange |
| USB-C (CCID smart-card) | ✅ | ❌ | iOS gives apps no arbitrary USB/CCID access |
| USB-C (CTAPHID for FIDO2) | ✅ | ❌ | No third-party CTAPHID/USB-HID access on iOS |

So **all USB functionality is on hold for now**, and FIDO2 is limited to the CTAP2 *NFC
APDU* binding (no CTAPHID). Fingerprint enrollment — which the original notes
requires USB even on Android — is out not available.

### To run on a device
1. A **Apple Developer account** (NFC entitlements required).
2. Apple must grant the **Near Field Communication Tag Reading** capability on the App ID.
3. `Info.plist` provides `NFCReaderUsageDescription`; the entitlements file lists
   every AID under `...iso7816.select-identifiers`. Keep that list in sync with
   `NFCTransport.AID`.



Or simply install it from the App Store.


<a href="https://apps.apple.com/app/id6785083417"><img src="appstore.svg" width=150 alt="Get it on AppStore" ></a>

NFC ISO7816 does **not** work in the iOS Simulator — test on a physical iPhone
(iPhone 7 or newer).

## Status by module

| Module | State | Notes |
|--------|-------|-------|
| OATH (TOTP/HOTP) | ✅ Implemented | List, live codes, add (QR + paste), delete (swipe), touch-required, HOTP counter. Core verified against RFC 4226/6238; PUT/DELETE framing tested against the YKOATH spec |
| Transport (NFC) | ✅ Implemented | APDU + GET RESPONSE chaining, extended length |
| MDS | ✅ Implemented | 102-entry bundled starter set + in-app update that fetches the live MDS3 JWT blob from mds3.fidoalliance.org. Info tab shows entry count, source, last-updated, and an update button. Resolves AAGUID→model/certification in the FIDO2 tab. Ported from fido/MdsRepository.kt |
| FIDO2 mgmt | ✅ Implemented (NFC) | Full management UI: getInfo, PIN retries, set/change PIN, alwaysUV toggle, list/delete passkeys. CBOR + PIN/UV v1/v2 crypto ported from `fido/ctap/`. Fingerprint enrollment omitted (needs held USB session) |
| OpenPGP (read) | 🟧 Skeleton | Needs Application-Related-Data BER-TLV parser |
| PIV (read) | 🟧 Skeleton | Needs DER/X.509 parser from `piv/` |
| Token2 OTP | ✅ Implemented | Auto-detected on scan. Read + manual-entry form (issuer/account/secret/algorithm/period/digits/touch) with QR populating editable fields, plus write/delete. ECDH-P256/AES crypto + codec ported from `token2/`, validated against spec §10.1/§10.2 |

Skeletons SELECT the correct AID and frame the right APDUs; the parsers/crypto
marked `PORTING NOTE` must be ported and re-validated against the same spec
vectors the original uses before they are trusted. They currently throw a clear
"not yet ported" error rather than returning unverified data.

## Layout

```
LibreKeyCompanion/
├── App/            App entry point + KeySession (NFC coordinator)
├── Transport/      APDU, KeyTransport protocol, NFCTransport (CoreNFC)
├── OATH/           RFC 4226/6238 core, YKOATH applet, Base32, otpauth, TLV
├── Token2/         Token2 on-device OTP (skeleton)
├── FIDO/CTAP/      CTAP2-over-NFC management (skeleton)
├── OpenPGP/        OpenPGP card read-only (skeleton)
├── PIV/            PIV read-only (skeleton)
├── MDS/            FIDO metadata model + repository
├── UI/             SwiftUI: Info / OTP / FIDO2 tabs
└── Resources/      Info.plist, entitlements, asset catalog
LibreKeyCompanionTests/   Spec-vector tests (RFC 4226/6238, Base32, TLV, APDU)
```

## Screenshots

<img width="350" alt="screenshot 1" src="https://github.com/user-attachments/assets/a054f66f-a228-415a-b710-0b751ece5c12" />


  <img width="350" alt="screenshot 2" src="https://github.com/user-attachments/assets/755f7df2-b521-4bfd-b3ce-63e38911a66c" />

  
  <img width="350" alt="screenshot 3" src="https://github.com/user-attachments/assets/1685d283-67ce-4d8e-bf9b-1473f5b0f086" />

  
  <img width="350" alt="screenshot 4" src="https://github.com/user-attachments/assets/0a3cf92f-ba7b-4ac3-8585-da79f27e0478" />

  
  <img width="350" alt="screenshot 5" src="https://github.com/user-attachments/assets/c43e88a2-89d9-4194-ab2c-165ec4b877b2" />

<img width="350" alt="image" src="https://github.com/user-attachments/assets/48cbc6fa-12b4-47f4-809a-1f71cc8c6757" />

## Correctness

Following the original's principle of verifying security-sensitive logic against
**published spec test vectors**, `OATHCoreTests` checks the full RFC 4226 and
RFC 6238 vector sets, Base32 decoding, otpauth parsing, TLV round-trips, and
extended-length APDU encoding. `YKOATHFramingTests` uses a mock transport to
assert the PUT/DELETE byte layout — touch property byte (0x78 0x02), 4-byte HOTP
IMF (0x7A), and the DELETE name TLV — against the
[YKOATH protocol spec](https://developers.yubico.com/OATH/YKOATH_Protocol.html).
The HOTP/TOTP math and the IMF/property encoding were additionally cross-checked
against Python during development.

## Adding credentials

The OTP tab adds credentials by **QR scan** (AVFoundation, needs
`NSCameraUsageDescription` + a physical device) or by pasting an `otpauth://`
URI, with an optional **require-touch** toggle. Deleting is swipe-to-delete on a
credential row. Each operation is one NFC tap.

## Brand assets

The app icon (`Assets.xcassets/AppIcon.appiconset/icon-1024.png`) and the in-app
logo (`Assets.xcassets/Logo.imageset`) are rasterized from the original Token2
`logo.svg`. The app icon is rendered full-bleed (squared corners, no alpha) so
iOS applies its own corner mask; the in-app logo keeps the rounded-square form
and transparency.  

## License

Inherits the original project's MIT license.
