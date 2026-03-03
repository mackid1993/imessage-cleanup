# iMessage Cleanup

A macOS app to view and remove ghost iMessage device registrations from Apple's IDS (Identity Directory Service) servers.

## What It Does

When Rustpush-based iMessage bridge instances crash, get reinstalled, or lose state without cleanly deregistering, they leave behind "ghost" device entries on Apple's servers. These ghost devices:

- Appear in iOS Settings > Messages > Text Message Forwarding
- Can interfere with message delivery (messages routed to dead devices)
- Accumulate over time with no built-in way to remove them

This tool authenticates with your Apple ID, lists all registered iMessage devices, and lets you delete the ghost entries one at a time.

## How It Works

1. **Sign in** with your Apple ID on the Mac running the app
2. **View** all iMessage devices registered under your account, sorted oldest first
3. **Identify** ghost devices (bridge instances show as "Mac-XXXXXX", with age and registration date)
4. **Delete** individual ghost devices by clicking the trash icon

### Technical Details

Each delete operation performs a full cycle to bypass Apple's per-push-token deregistration limit:

1. Creates a temporary APS (Apple Push Notification Service) connection with a fresh push token
2. Re-authenticates with Apple's IDS servers to get a fresh auth keypair
3. Registers on the temporary connection to obtain an identity certificate
4. Sends a targeted `id-deregister` request to remove the ghost device
5. Deregisters itself and tears down the temporary connection

The main connection is preserved for browsing the device list between deletes.

## Requirements

- **macOS 14.0+** (Sonoma or later)
- **Rust toolchain** (`cargo`) — installed automatically by build.sh if missing
- **CMake** — installed automatically via Homebrew if missing
- **Xcode Command Line Tools** (`swiftc`, `clang`)

## Building

```bash
git clone https://github.com/mackid1993/imessage-cleanup.git
cd imessage-cleanup
./build.sh
```

This will:
1. Build the Rust FFI library (`cleanup-ffi`)
2. Generate Swift bindings via UniFFI
3. Compile the SwiftUI app
4. Package it as `iMessage Cleanup.app`

Run with:
```bash
open "iMessage Cleanup.app"
```

## Project Structure

```
├── build.sh                    # Build script (Rust + Swift + .app bundle)
├── Cargo.toml                  # Rust workspace config
├── CleanupApp/                 # SwiftUI app
│   ├── App.swift               # App entry point, navigation, quit protection
│   ├── LoginView.swift         # Apple ID login + 2FA flow
│   ├── DeviceListView.swift    # Device list, delete UI, log panel
│   ├── IDSBridge.swift         # Log capture (stderr + Swift logs)
│   └── entitlements.plist      # IDS entitlements
├── crates/
│   └── cleanup-ffi/            # Rust FFI layer (UniFFI bindings)
│       └── src/
│           ├── lib.rs          # Main FFI: login, device listing, deregistration
│           ├── local_config.rs # macOS hardware identity (IOKit)
│           ├── hardware_info.m # Objective-C IOKit reader
│           └── util.rs         # Plist helpers
├── nac-validation/             # Apple APNs validation data generator
└── rustpush/                   # IDS protocol implementation (submodule)
```

## Safety

- The app warns you not to quit during delete operations (a temporary device registration is active)
- On sign out, the app deregisters itself to avoid creating a new ghost
- Cmd+Q is blocked while an operation is in flight
- Each device is deleted individually — there is no bulk delete to prevent accidental mass removal

## Acknowledgments

Built on top of [Matrix iMessage Bridge](https://github.com/lrhodin/imessage) for Apple IDS protocol support.
