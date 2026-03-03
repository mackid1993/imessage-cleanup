import SwiftUI
import UniformTypeIdentifiers

struct DeviceListView: View {
    @EnvironmentObject var appState: AppState
    @ObservedObject var logCapture = LogCapture.shared

    @State private var devices: [DeviceInfo] = []
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var deletingTokens: Set<String> = []
    @State private var showLogs = true

    /// Devices sorted oldest registration first (ghosts at top)
    private var sortedDevices: [DeviceInfo] {
        devices.sorted { a, b in
            // Devices with epoch 0 (unknown) sort to top as likely ghosts
            if a.registeredEpoch == 0 && b.registeredEpoch != 0 { return true }
            if b.registeredEpoch == 0 && a.registeredEpoch != 0 { return false }
            return a.registeredEpoch < b.registeredEpoch
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("iMessage Device Cleanup")
                    .font(.title2)
                    .fontWeight(.semibold)

                Spacer()

                Button(action: refreshDevices) {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(isLoading)
                .help("Refresh device list")

                Button("Save Logs") {
                    saveLogs()
                }
                .help("Save debug logs to file")

                Button("Sign Out") {
                    appState.logout()
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .disabled(appState.operationInFlight)
            }
            .padding()

            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.yellow)
                Text("You must sign out before quitting the app, or you will leave a ghost device.")
                    .font(.callout)
                    .fontWeight(.medium)
                Spacer()
            }
            .padding(.horizontal)
            .padding(.vertical, 6)
            .background(Color.yellow.opacity(0.12))

            Divider()

            if appState.operationInFlight {
                HStack {
                    ProgressView()
                        .controlSize(.small)
                    Text("Operation in progress — do NOT quit the app.")
                        .font(.callout)
                        .fontWeight(.medium)
                        .foregroundColor(.white)
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color.red.opacity(0.85))
            }

            if !errorMessage.isEmpty {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                    Text(errorMessage)
                        .font(.callout)
                        .foregroundColor(.secondary)
                    Spacer()
                    Button("Dismiss") { errorMessage = "" }
                        .buttonStyle(.borderless)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color.orange.opacity(0.1))
            }

            // Main content
            if isLoading && devices.isEmpty {
                Spacer()
                ProgressView("Loading devices...")
                Spacer()
            } else if devices.isEmpty {
                Spacer()
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.circle")
                        .font(.largeTitle)
                        .foregroundColor(.green)
                    Text("No devices registered.")
                        .foregroundColor(.secondary)
                }
                Spacer()
            } else {
                deviceListView
            }

            // Log panel
            Divider()
            VStack(spacing: 0) {
                HStack {
                    Button(action: { withAnimation { showLogs.toggle() } }) {
                        HStack(spacing: 4) {
                            Image(systemName: showLogs ? "chevron.down" : "chevron.right")
                                .frame(width: 12)
                            Text("Logs")
                                .font(.caption)
                                .fontWeight(.medium)
                        }
                    }
                    .buttonStyle(.borderless)

                    Spacer()

                    if showLogs {
                        Button("Clear") { logCapture.lines.removeAll() }
                            .font(.caption)
                            .buttonStyle(.borderless)
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(logCapture.getText(), forType: .string)
                        }
                        .font(.caption)
                        .buttonStyle(.borderless)
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 4)

                if showLogs {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 1) {
                                ForEach(Array(logCapture.lines.enumerated()), id: \.offset) { idx, line in
                                    Text(line)
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundColor(.secondary)
                                        .textSelection(.enabled)
                                        .id(idx)
                                }
                            }
                            .padding(.horizontal)
                        }
                        .frame(height: 150)
                        .background(Color(nsColor: .textBackgroundColor).opacity(0.5))
                        .onChange(of: logCapture.lines.count) { _ in
                            if let last = logCapture.lines.indices.last {
                                proxy.scrollTo(last, anchor: .bottom)
                            }
                        }
                    }
                }
            }
        }
        .frame(minWidth: 700, minHeight: 600)
        .onAppear {
            LogCapture.shared.start()
            refreshDevices()
        }
        .overlay {
            if isLoading && !devices.isEmpty {
                ProgressView()
                    .padding(8)
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8))
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
                    .padding()
            }
        }
    }

    // MARK: - Device List

    private var deviceListView: some View {
        VStack(spacing: 0) {
            // Info bar
            HStack(spacing: 16) {
                Label("Rustpush", systemImage: "server.rack")
                    .font(.caption)
                    .foregroundColor(.orange)
                Label("Apple Device", systemImage: "iphone")
                    .font(.caption)
                    .foregroundColor(.blue)
                Spacer()
                Text("\(devices.count) device(s) registered")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal)
            .padding(.vertical, 6)

            Divider()

            List {
                ForEach(sortedDevices, id: \.tokenHex) { device in
                    HStack(spacing: 12) {
                        DeviceRow(device: device, style: .normal)

                        if deletingTokens.contains(device.tokenHex) {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Button(role: .destructive) {
                                deleteDevice(device)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .help("Remove this device registration")
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    // MARK: - Actions

    private func saveLogs() {
        let panel = NSSavePanel()
        panel.title = "Save Logs"
        panel.nameFieldStringValue = "cleanup-log.txt"
        panel.allowedContentTypes = [.plainText]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let text = LogCapture.shared.getText() + "\n" + CleanupLog.shared.getText() + "\n"
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            logCapture.append("Logs saved to \(url.path)")
        } catch {
            errorMessage = "Failed to save logs: \(error.localizedDescription)"
        }
    }

    private func refreshDevices() {
        guard let users = appState.users,
              let connection = appState.connection else { return }

        isLoading = true
        errorMessage = ""

        Task {
            do {
                let result = try await getDevices(users: users, connection: connection)
                // Filter out our own cleanup tool registration
                let ourToken = connection.getTokenHex()
                let filtered = result.filter { $0.tokenHex != ourToken }
                devices = filtered
                isLoading = false
            } catch {
                errorMessage = "Failed to load devices: \(describeError(error))"
                isLoading = false
            }
        }
    }

    private func deleteDevice(_ device: DeviceInfo) {
        guard let users = appState.users,
              let connection = appState.connection,
              let config = appState.config else { return }

        deletingTokens.insert(device.tokenHex)
        errorMessage = ""
        appState.operationInFlight = true

        Task {
            defer { appState.operationInFlight = false }
            do {
                // Use register-then-deregister approach for full IDS credentials
                let status = try await registerAndDeregisterDevice(
                    users: users,
                    connection: connection,
                    config: config,
                    targetTokenBase64: device.tokenBase64
                )
                logCapture.append("[Delete] Device \(device.deviceName): IDS status \(status)")

                // Refresh and check if the specific target is gone
                if let users = appState.users,
                   let connection = appState.connection {
                    let updated = try await getDevices(users: users, connection: connection)
                    let ourToken = connection.getTokenHex()
                    let filtered = updated.filter { $0.tokenHex != ourToken }
                    let beforeCount = devices.count
                    devices = filtered
                    deletingTokens.remove(device.tokenHex)

                    let targetGone = !filtered.contains(where: { $0.tokenHex == device.tokenHex })
                    if targetGone {
                        logCapture.append("[Delete] Success! \(device.deviceName) removed. \(beforeCount) -> \(filtered.count)")
                    } else {
                        errorMessage = "Status \(status) — device still registered. Check logs."
                    }
                }
            } catch {
                deletingTokens.remove(device.tokenHex)
                errorMessage = "Failed: \(describeError(error))"
                logCapture.append("[Delete] Error: \(error)")
            }
        }
    }

}

// MARK: - Device Row

enum DeviceRowStyle {
    case normal
    case reRegistered
    case removed
}

struct DeviceRow: View {
    let device: DeviceInfo
    var style: DeviceRowStyle = .normal

    private var isBridge: Bool {
        device.deviceName.hasPrefix("Mac-")
    }

    private var ageSeconds: Double {
        guard device.registeredEpoch > 0 else { return .infinity }
        return Date.now.timeIntervalSince1970 - device.registeredEpoch
    }

    /// Registered in the last 24 hours — likely still active
    private var isRecentlyActive: Bool {
        ageSeconds < 86400
    }

    /// Registered more than 7 days ago — likely a ghost
    private var isOldRegistration: Bool {
        ageSeconds > 7 * 86400
    }

    private static func formatAge(_ epoch: Double) -> String {
        guard epoch > 0 else { return "Unknown date" }
        let age = Date.now.timeIntervalSince1970 - epoch
        if age < 3600 { return "\(Int(age / 60))m ago" }
        if age < 86400 { return "\(Int(age / 3600))h ago" }
        if age < 86400 * 30 { return "\(Int(age / 86400))d ago" }
        return "\(Int(age / (86400 * 30)))mo ago"
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    private static func formatDate(_ epoch: Double) -> String {
        let date = Date(timeIntervalSince1970: epoch)
        return dateFormatter.string(from: date)
    }

    var body: some View {
        HStack(spacing: 12) {
            // Status icon
            switch style {
            case .normal:
                Image(systemName: isBridge ? "server.rack" : "iphone")
                    .foregroundColor(isBridge ? .orange : .blue)
                    .frame(width: 24)
            case .reRegistered:
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .frame(width: 24)
            case .removed:
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.red)
                    .frame(width: 24)
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(device.deviceName)
                        .fontWeight(.medium)
                        .if(style == .removed) { $0.strikethrough().opacity(0.6) }

                    if isBridge {
                        Text("Rustpush")
                            .font(.caption2)
                            .fontWeight(.semibold)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Color.orange.opacity(0.2))
                            .foregroundColor(.orange)
                            .cornerRadius(3)
                    }

                    if style == .normal && isRecentlyActive {
                        Text("Active")
                            .font(.caption2)
                            .fontWeight(.semibold)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Color.green.opacity(0.2))
                            .foregroundColor(.green)
                            .cornerRadius(3)
                    }
                }

                HStack(spacing: 8) {
                    if device.registeredEpoch > 0 {
                        Text(Self.formatDate(device.registeredEpoch))
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("(\(Self.formatAge(device.registeredEpoch)))")
                            .font(.caption)
                            .foregroundColor(isOldRegistration ? .red : .secondary)
                    } else {
                        Text("Unknown date")
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                    Text("\(device.identities.count) handle(s)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()
        }
        .padding(.vertical, 4)
    }
}

// MARK: - View Extension

extension View {
    @ViewBuilder
    func `if`<Transform: View>(_ condition: Bool, transform: (Self) -> Transform) -> some View {
        if condition {
            transform(self)
        } else {
            self
        }
    }
}
