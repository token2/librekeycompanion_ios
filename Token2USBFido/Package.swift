// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "Token2USBFido",
    platforms: [.iOS(.v16), .macOS(.v12)],
    products: [
        .library(name: "Token2USBFido", targets: ["Token2USBFido"]),
    ],
    targets: [
        .target(name: "Token2USBFido"),
        .testTarget(name: "Token2USBFidoTests", dependencies: ["Token2USBFido"]),
    ]
)
