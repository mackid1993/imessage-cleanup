#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="iMessage Cleanup"
BUNDLE_ID="com.imessage.cleanup"
APP_DIR="${APP_NAME}.app"

# === Install dependencies ===
echo "=== Checking dependencies ==="

if ! command -v cargo &>/dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

if ! command -v cmake &>/dev/null; then
    echo "Installing cmake..."
    brew install cmake
fi

# === Build Rust static library ===
echo "=== Building cleanup-ffi (Rust) ==="
cargo build --release -p cleanup-ffi

# === Generate Swift bindings from compiled library ===
echo "=== Generating Swift bindings (uniffi) ==="
cargo run --release --bin uniffi-bindgen generate \
    --library target/release/libcleanup_ffi.a \
    --language swift \
    --out-dir CleanupApp/Bridge/

# === Compile SwiftUI app ===
echo "=== Compiling SwiftUI app ==="
swiftc \
    -parse-as-library \
    -import-objc-header CleanupApp/Bridge/cleanup_ffiFFI.h \
    -L target/release \
    -lcleanup_ffi \
    -framework Foundation \
    -framework IOKit \
    -framework Security \
    -framework SystemConfiguration \
    -framework CoreServices \
    -framework SwiftUI \
    -framework AppKit \
    -lresolv \
    -lz \
    CleanupApp/Bridge/cleanup_ffi.swift \
    CleanupApp/App.swift \
    CleanupApp/LoginView.swift \
    CleanupApp/DeviceListView.swift \
    CleanupApp/IDSBridge.swift \
    -o imessage-cleanup

# === Package as .app bundle ===
echo "=== Creating ${APP_DIR} ==="
rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"

cp imessage-cleanup "${APP_DIR}/Contents/MacOS/imessage-cleanup"


cat > "${APP_DIR}/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>imessage-cleanup</string>
    <key>CFBundleIdentifier</key>
    <string>com.imessage.cleanup</string>
    <key>CFBundleName</key>
    <string>iMessage Cleanup</string>
    <key>CFBundleDisplayName</key>
    <string>iMessage Cleanup</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticTermination</key>
    <true/>
</dict>
</plist>
PLIST

xattr -cr "${APP_DIR}"

echo "Built: ./${APP_DIR}"
echo "Run with: open \"${APP_DIR}\""
