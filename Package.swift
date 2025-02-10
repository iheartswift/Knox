// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Knox",
    platforms: [
        .iOS(.v17),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "Knox",
            targets: ["Knox"]
        )
    ],
    targets: [
        .target(
            name: "Knox",
            dependencies: []
        ),
        // New test target:
        .testTarget(
            name: "KnoxTests",
            dependencies: ["Knox"]
        )
    ]
)
