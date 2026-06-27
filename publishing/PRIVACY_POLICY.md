# Privacy Policy — Libre Key Companion

_Last updated: June 2026_

Libre Key Companion ("the app") is a tool for managing hardware security keys
(FIDO2/CTAP2, OATH TOTP/HOTP, Token2 on-device OTP, PIV, and OpenPGP) over NFC
and USB-C. This policy explains what the app does and does not do with your data.

## Summary

**The app does not collect, store, transmit, sell, or share any personal data.**
There is no account, no analytics, no advertising, and no tracking.

## What stays on your device

- **One-time passcodes and key data** read from your security key are shown on
  screen only. They are not written to disk and are cleared when you read a new
  key or unplug it.
- **Credentials you add** (e.g. a TOTP secret via QR scan or `otpauth://` URI)
  are written **to your hardware key**, not to the phone.
- **A cached copy of the public FIDO Alliance metadata** (a list mapping
  authenticator model identifiers to names and certification levels) is stored
  in the app's private container so lookups work offline. It contains no
  personal data.

## Network access

The app makes a single, optional network request: when you tap "Update from
FIDO Alliance," it downloads the public FIDO Metadata Service (MDS) blob from
`https://mds3.fidoalliance.org/`. This request sends **no** personal data — it
only retrieves a public file. No other network connections are made.

## Permissions

- **NFC** — to communicate with your security key over NFC.
- **Camera** — only when you choose to scan a QR code while adding a credential.
  Images are processed on-device and never stored or transmitted.

## Data collection

None. The app declares no collected data types in its App Store privacy
information and ships a privacy manifest reflecting this.

## Children

The app is a security utility and is not directed at children. It collects no
data from anyone.

## Contact

For questions about this policy, contact: support@token2.com

## Changes

If this policy changes, the updated version will be posted at the app's support
URL with a new "last updated" date.
