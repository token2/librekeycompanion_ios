import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// A header card showing an authenticator's MDS-sourced icon, model name, and
/// FIDO certification badge (L1/L2/…). Used wherever a known AAGUID is resolved.
struct DeviceHeaderCard: View {
    let entry: MDSEntry

    var body: some View {
        HStack(spacing: 14) {
            iconView
                .frame(width: 44, height: 44)
            VStack(alignment: .leading, spacing: 4) {
                Text(entry.description)
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
                if let badge = entry.certBadge {
                    CertBadge(text: badge, certified: true)
                } else if entry.status == "NOT_FIDO_CERTIFIED" {
                    CertBadge(text: "Not certified", certified: false)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private var iconView: some View {
        #if canImport(UIKit)
        if let data = entry.iconData, let ui = UIImage(data: data) {
            Image(uiImage: ui)
                .resizable()
                .interpolation(.high)
                .aspectRatio(contentMode: .fit)
        } else {
            placeholder
        }
        #else
        placeholder
        #endif
    }

    private var placeholder: some View {
        Image(systemName: "lock.shield.fill")
            .resizable()
            .aspectRatio(contentMode: .fit)
            .foregroundStyle(.secondary)
            .padding(6)
    }
}

/// Small pill showing the certification level.
private struct CertBadge: View {
    let text: String
    let certified: Bool

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: certified ? "checkmark.seal.fill" : "seal")
                .font(.caption2)
            Text(text)
                .font(.caption.weight(.medium))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(
            Capsule().fill((certified ? Color.green : Color.secondary).opacity(0.15))
        )
        .foregroundStyle(certified ? Color.green : Color.secondary)
    }
}
