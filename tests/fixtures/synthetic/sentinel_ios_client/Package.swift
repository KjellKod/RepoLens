// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "sentinel-ios-client",
    dependencies: [
        .package(url: "https://example.invalid/sentinel-swift-runtime.git", exact: "1.0.0")
    ],
    targets: [
        .target(
            name: "SentinelIOSClient",
            dependencies: [
                .product(name: "SentinelSwiftRuntime", package: "sentinel-swift-runtime")
            ]
        )
    ]
)
