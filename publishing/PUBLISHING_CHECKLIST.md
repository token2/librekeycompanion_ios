# Publishing Checklist — Libre Key Companion

Toolchain (Xcode 26.x) is ready. The project now includes the privacy manifest,
encryption declaration, and version 1.0.0. Work top to bottom.

## A. In Xcode (one-time project setup)

1. Open LibreKeyCompanion.xcodeproj in Xcode 26.
2. Select the target → Signing & Capabilities:
   - Team: your Apple Developer team.
   - Signing: Automatic.
   - Confirm the "Near Field Communication Tag Reading" capability is present
     (it pairs with the entitlements file already in the project).
3. Confirm Bundle Identifier: com.token2.lkcompanion
   - Register this exact ID in the Developer portal (Certificates, IDs & Profiles
     → Identifiers) and enable the NFC Tag Reading capability on it.
4. Build settings sanity check:
   - Deployment target: iOS 16.0 (keep — building with the 26 SDK does NOT force
     a higher deployment target).
   - Base SDK: iOS 26 (default in Xcode 26).
5. Provide assets:
   - App icon: 1024×1024 is already in Assets.xcassets (verify it shows).
   - Launch screen: the project uses an empty UILaunchScreen dict (a blank launch
     screen). Optional: design a simple one.
6. Build and run on a real device. Test, with a key:
   - NFC: OATH read/add/delete, Token2 OTP incl. touch-required reveal, FIDO2
     info/PIN/passkeys.
   - USB-C: plug in, confirm auto-read of OATH/Token2/PIV/OpenPGP.

## B. Privacy & compliance (already in the project — just verify)

7. PrivacyInfo.xcprivacy is bundled (declares file-timestamp reason C617.1, no
   data collection). Nothing to change unless you add new APIs/SDKs.
8. Info.plist has ITSAppUsesNonExemptEncryption = false (standard crypto only).
9. Usage strings present: NFCReaderUsageDescription, NSCameraUsageDescription.

## C. App Store Connect (web)

10. Create the app record: My Apps → + → New App.
    - Platform: iOS. Name, primary language, bundle ID, SKU (any unique string).
11. Fill App Information: category Utilities, age rating questionnaire (current
    version — answer it fresh; stale answers block submission).
12. Pricing and Availability: Free (presumably), choose territories.
13. App Privacy: choose "Data Not Collected." (See PRIVACY_POLICY.md and the
    privacy manifest — the app collects nothing.) Add the Privacy Policy URL.
14. Prepare the version (1.0.0) page:
    - Description, keywords, subtitle, promo text → from APP_STORE_LISTING.md
    - Support URL, marketing URL.
    - Screenshots: required iPhone sizes (at least 6.9"/6.5"). Capture from a
      device or simulator. (Reads need a key, but the tab UI, MDS update, add
      form, and QR scanner screens are all screenshot-able.)
15. App Review Information: paste REVIEW_NOTES.md. Note that hardware is required
    to test; offer a demo video. Add a contact phone/email.

## D. Build upload

16. In Xcode: set the build number, then Product → Archive.
17. In Organizer: Validate App (fix anything it flags — privacy manifest,
    entitlements, missing icons surface here). Use notarytool/Transporter only if
    not uploading directly; the Application Loader is discontinued.
18. Distribute App → App Store Connect → Upload.

## E. TestFlight, then submit

19. Once the build processes, add it to TestFlight and test on device (internal
    testers don't need review). Confirm NFC + USB flows on real hardware.
20. Back on the version page, attach the build, then Add for Review → Submit.
21. Choose release option: manual, automatic, or phased.

## Likely review questions to preempt
- Why NFC/Camera? → answered by usage strings + review notes.
- What is the data flow? → none collected; one public metadata fetch.
- Trademark "Token2" → app is published by Token2 (make sure the seller/
  developer name matches).
