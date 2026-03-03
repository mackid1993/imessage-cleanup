import SwiftUI

// MARK: - App State

enum AppScreen {
    case login
    case devices
}

@MainActor
class AppState: ObservableObject {
    @Published var screen: AppScreen = .login
    @Published var config: WrappedOsConfig?
    @Published var connection: WrappedApsConnection?
    @Published var users: WrappedIdsUsers?
    @Published var globalError: String?
    /// True while a register-then-deregister operation is in flight.
    /// When true, the user MUST NOT quit or they'll leave a ghost device.
    @Published var operationInFlight = false

    func navigateToDevices() {
        screen = .devices
    }

    func logout() {
        guard !operationInFlight else {
            globalError = "Cannot sign out while a delete operation is in progress. Please wait for it to finish."
            return
        }
        if let users = users, let connection = connection, let config = config {
            Task {
                try? await cleanupDeregister(users: users, connection: connection, config: config)
                await MainActor.run {
                    self.users = nil
                    self.screen = .login
                }
            }
        } else {
            users = nil
            screen = .login
        }
    }
}

/// Extract the actual message from CleanupError since Swift's default
/// Error conformance loses the associated value.
func describeError(_ error: Error) -> String {
    if case CleanupError.Generic(let msg) = error {
        return msg
    }
    return error.localizedDescription
}

// MARK: - App Entry Point

@main
struct CleanupApp: App {
    @StateObject private var appState = AppState()

    init() {
        initCleanup()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .frame(minWidth: 700, minHeight: 600)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
                    if appState.operationInFlight {
                        // Last resort: warn user. In practice the alert below should prevent this.
                        print("WARNING: App terminating with operation in flight! Ghost device may be left behind.")
                    }
                }
        }
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .appTermination) {
                Button("Quit iMessage Cleanup") {
                    if appState.operationInFlight {
                        appState.globalError = "Cannot quit while a delete operation is in progress. A temporary device registration is active — quitting now would leave a ghost. Please wait."
                    } else {
                        NSApplication.shared.terminate(nil)
                    }
                }
                .keyboardShortcut("q")
            }
        }
    }
}

// MARK: - Root Content View

struct ContentView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        Group {
            switch appState.screen {
            case .login:
                LoginView()
            case .devices:
                DeviceListView()
            }
        }
        .alert("Error", isPresented: Binding(
            get: { appState.globalError != nil },
            set: { if !$0 { appState.globalError = nil } }
        )) {
            Button("OK") { appState.globalError = nil }
        } message: {
            Text(appState.globalError ?? "")
        }
    }
}
