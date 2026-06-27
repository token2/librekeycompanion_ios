# App Review Notes — Libre Key Companion

Paste this into the "Notes" field of the App Review Information section in
App Store Connect.

---

This app manages hardware security keys (FIDO2/CTAP2, OATH OTP, Token2 OTP, PIV,
OpenPGP) over NFC and USB-C. It is a companion utility, similar in category to
Yubico Authenticator.

IMPORTANT — PHYSICAL HARDWARE IS REQUIRED TO TEST
Most functionality only does something when a compatible security key is present.
Without a key, the app shows its three tabs (Info, OTP, FIDO2) and the "Read
Device" buttons, but reads will simply time out or report no key found, which is
expected.

HOW IT WORKS WITHOUT A KEY (what a reviewer can verify)
• The app launches to a tab bar: Info, OTP, FIDO2.
• Tapping "Read Device" starts an NFC session (a system NFC sheet appears). With
  no key, it times out — this is normal.
• The "Update from FIDO Alliance" button on the Info tab works without a key: it
  downloads the public FIDO metadata file and updates the on-screen entry count.
• The QR scanner (OTP tab → + → Scan QR) requests camera permission and can be
  demonstrated without a key, though saving requires a key.

PERMISSIONS
• NFC (Core NFC, ISO 7816 tag reading): to talk to the security key.
• Camera: only for scanning otpauth QR codes when the user adds a credential.

USB-C
On iOS 16.1+, the app reads CCID-interface applets (OATH, Token2 OTP, PIV,
OpenPGP) from a USB-C security key via CryptoTokenKit (TKSmartCard). FIDO2
management uses the key's CTAPHID interface, which iOS does not expose to
third-party apps, so FIDO2 is NFC-only. No special entitlement is required for
TKSmartCard APDU access on iOS.

PRIVACY
No data is collected, stored off-device, or transmitted. The only network call
fetches the public FIDO Alliance metadata blob and sends no user data. A privacy
manifest (PrivacyInfo.xcprivacy) is included; it declares one Required-Reason API
(file timestamp, reason C617.1, used to show when the metadata cache was last
updated) and no collected data types.

ENCRYPTION
The app uses only standard, exempt cryptography (AES, ECDH, HKDF, SHA via
CryptoKit/CommonCrypto) to communicate with security keys. ITSAppUsesNonExempt-
Encryption is set to false.

BRAND
The app is published by Token2, which owns the Token2 brand referenced in the app.

If you would like a demonstration video of the key-management flows, we can
provide one — please let us know.
