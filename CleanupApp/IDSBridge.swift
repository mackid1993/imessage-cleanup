import Foundation

/// Post a Darwin notification via notifyutil CLI
func postNotification(_ name: String) {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/notifyutil")
    task.arguments = ["-p", name]
    try? task.run()
    task.waitUntilExit()
}

/// Observable log that captures stderr (Rust env_logger output) and Swift print() calls.
@MainActor
class LogCapture: ObservableObject {
    static let shared = LogCapture()
    @Published var lines: [String] = []
    private var stderrPipe: Pipe?
    private var stdoutPipe: Pipe?

    func start() {
        // Capture stderr (Rust logs go here via env_logger)
        let errPipe = Pipe()
        stderrPipe = errPipe
        dup2(errPipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO)
        errPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let str = String(data: data, encoding: .utf8) else { return }
            let newLines = str.split(separator: "\n", omittingEmptySubsequences: false)
                .map(String.init)
                .filter { !$0.isEmpty }
            DispatchQueue.main.async {
                self?.lines.append(contentsOf: newLines)
                // Keep last 500 lines
                if let count = self?.lines.count, count > 500 {
                    self?.lines.removeFirst(count - 500)
                }
            }
        }
    }

    func append(_ msg: String) {
        lines.append(msg)
        if lines.count > 500 {
            lines.removeFirst(lines.count - 500)
        }
    }

    func getText() -> String { lines.joined(separator: "\n") }

    func save() {
        let url = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("cleanup-log.txt")
        let text = getText() + "\n"
        try? text.write(to: url, atomically: true, encoding: .utf8)
        append("Logs saved to \(url.path)")
    }
}

class CleanupLog {
    static let shared = CleanupLog()
    private var lines: [String] = []

    func log(_ msg: String) {
        let line = "[\(Self.ts)] \(msg)"
        print(line)
        lines.append(line)
        DispatchQueue.main.async {
            LogCapture.shared.append(line)
        }
    }

    func save() {
        let text = lines.joined(separator: "\n") + "\n"
        let url = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("cleanup-log.txt")
        try? text.write(to: url, atomically: true, encoding: .utf8)
        print("Logs saved to \(url.path)")
    }

    func getText() -> String { lines.joined(separator: "\n") }

    private static var ts: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f.string(from: Date())
    }
}

private let L = CleanupLog.shared

class IDSBridge {
    static let shared = IDSBridge()
    private init() {}

    func unregisterAccount() async throws {
        L.log("========== STARTING CLEANUP ==========")

        let accountID = "B2CBEC5C-2BD2-4CB2-AA0C-78A2C7471785"

        // Step 1: Clear local IDS registration state
        L.log("--- Step 1: Clearing local IDS state ---")

        if let idsPrefs = UserDefaults(suiteName: "com.apple.imservice.ids.iMessage") {
            idsPrefs.removeObject(forKey: "ActiveAccounts")
            idsPrefs.removeObject(forKey: "OnlineAccounts")
            idsPrefs.synchronize()
            L.log("  Cleared ActiveAccounts/OnlineAccounts")
        }

        if let idsdPrefs = UserDefaults(suiteName: "com.apple.identityservicesd") {
            let oldHash = idsdPrefs.string(forKey: "ReRegisteredForDevicesHash") ?? "none"
            let oldCount = idsdPrefs.integer(forKey: "ReRegisteredForDevices")
            L.log("  ReRegisteredForDevices=\(oldCount) hash=\(oldHash)")
            idsdPrefs.removeObject(forKey: "ReRegisteredForDevicesHash")
            idsdPrefs.removeObject(forKey: "ReRegisteredForDevices")
            idsdPrefs.synchronize()
            L.log("  Cleared registration hash to force re-registration")
        }

        try await Task.sleep(nanoseconds: 1_000_000_000)

        // Step 2: Post Darwin notifications
        L.log("--- Step 2: Posting Darwin notifications ---")
        let notifications = [
            "com.apple.registration",
            "com.apple.Registration",
            "com.apple.IDSRegistrationController",
            "com.apple.identityservices.registration-hbi",
        ]
        for name in notifications {
            postNotification(name)
            L.log("  Posted \(name)")
        }

        try await Task.sleep(nanoseconds: 1_000_000_000)

        // Step 3: Kill imagent to force launchd restart
        L.log("--- Step 3: Restarting imagent ---")
        let killTask = Process()
        killTask.executableURL = URL(fileURLWithPath: "/usr/bin/killall")
        killTask.arguments = ["imagent"]
        let pipe = Pipe()
        killTask.standardOutput = pipe
        killTask.standardError = pipe
        do {
            try killTask.run()
            killTask.waitUntilExit()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            L.log("  killall imagent: exit=\(killTask.terminationStatus) \(output)")
        } catch {
            L.log("  killall imagent error: \(error)")
        }

        L.log("  Waiting 5s for imagent to restart...")
        try await Task.sleep(nanoseconds: 5_000_000_000)

        // Verify imagent restarted
        let checkTask = Process()
        checkTask.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        checkTask.arguments = ["imagent"]
        let checkPipe = Pipe()
        checkTask.standardOutput = checkPipe
        try? checkTask.run()
        checkTask.waitUntilExit()
        let pid = String(data: checkPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "?"
        L.log("  imagent PID: \(pid)")

        // Step 4: Restore account preferences
        L.log("--- Step 4: Restoring account prefs ---")
        if let idsPrefs = UserDefaults(suiteName: "com.apple.imservice.ids.iMessage") {
            idsPrefs.set([accountID], forKey: "ActiveAccounts")
            idsPrefs.set([accountID], forKey: "OnlineAccounts")
            idsPrefs.synchronize()
            L.log("  Restored ActiveAccounts/OnlineAccounts")
        }

        // Step 5: Post notifications again to kick fresh registration
        L.log("--- Step 5: Kicking registration ---")
        postNotification("com.apple.registration")
        postNotification("com.apple.IDSRegistrationController")
        L.log("  Posted registration notifications")

        L.log("========== CLEANUP COMPLETE ==========")
        L.log("Waiting 15s for re-registration...")
    }

    func disconnect() {}
}

enum IDSError: LocalizedError {
    case frameworkNotFound(String)
    case classNotFound(String)
    case noAccountFound
    case methodNotAvailable(String)

    var errorDescription: String? {
        switch self {
        case .frameworkNotFound(let name): return "Failed to load \(name).framework"
        case .classNotFound(let name): return "\(name) not found in runtime"
        case .noAccountFound: return "Could not find iMessage account"
        case .methodNotAvailable(let name): return "Method \(name) not available"
        }
    }
}
