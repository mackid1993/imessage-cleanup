import SwiftUI

struct LoginView: View {
    @EnvironmentObject var appState: AppState

    @State private var appleId = ""
    @State private var password = ""
    @State private var twoFACode = ""
    @State private var isLoading = false
    @State private var statusMessage = ""
    @State private var errorMessage = ""
    @State private var loginSession: LoginSession?
    @State private var showTwoFA = false

    var body: some View {
        VStack(spacing: 20) {
            Text("iMessage Device Cleanup")
                .font(.title)
                .fontWeight(.semibold)

            Text("Sign in with your Apple ID to view and manage registered iMessage devices.")
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            VStack(spacing: 12) {
                TextField("Apple ID", text: $appleId)
                    .textFieldStyle(.roundedBorder)
                    .disabled(isLoading || showTwoFA)
                    .textContentType(.username)
                    .onSubmit { if !showTwoFA { startLogin() } }

                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .disabled(isLoading || showTwoFA)
                    .textContentType(.password)
                    .onSubmit { if !showTwoFA { startLogin() } }
            }
            .frame(maxWidth: 300)

            if showTwoFA {
                VStack(spacing: 8) {
                    Text("Enter the 2FA code sent to your trusted device.")
                        .font(.callout)
                        .foregroundColor(.secondary)

                    TextField("6-digit code", text: $twoFACode)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 180)
                        .multilineTextAlignment(.center)
                        .disabled(isLoading)
                        .onSubmit { submitTwoFA() }
                }
            }

            if !statusMessage.isEmpty {
                Text(statusMessage)
                    .font(.callout)
                    .foregroundColor(.blue)
            }

            if !errorMessage.isEmpty {
                Text(errorMessage)
                    .font(.callout)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            if showTwoFA {
                Button("Verify Code") { submitTwoFA() }
                    .buttonStyle(.borderedProminent)
                    .disabled(isLoading || twoFACode.count < 4)
            } else {
                Button("Sign In") { startLogin() }
                    .buttonStyle(.borderedProminent)
                    .disabled(isLoading || appleId.isEmpty || password.isEmpty)
            }

            if isLoading {
                ProgressView()
                    .scaleEffect(0.8)
            }
        }
        .padding(40)
    }

    // MARK: - Login Flow

    private func startLogin() {
        guard !appleId.isEmpty, !password.isEmpty else { return }
        isLoading = true
        errorMessage = ""
        statusMessage = "Connecting to Apple..."

        Task {
            do {
                // Step 1: Create hardware config
                statusMessage = "Reading hardware identity..."
                if appState.config == nil {
                    appState.config = try createConfig()
                }
                guard let config = appState.config else { return }

                // Step 2: Connect to APS
                statusMessage = "Connecting to push service..."
                if appState.connection == nil {
                    let state = WrappedApsState(string: nil)
                    appState.connection = await connect(config: config, state: state)
                }
                guard let connection = appState.connection else { return }

                // Step 3: Start Apple ID login (SRP auth)
                statusMessage = "Authenticating..."
                let session = try await loginStart(
                    appleId: appleId,
                    password: password,
                    config: config,
                    connection: connection
                )
                loginSession = session

                if session.needs2fa() {
                    showTwoFA = true
                    statusMessage = "Waiting for 2FA code..."
                    isLoading = false
                } else {
                    await finishLogin(session: session)
                }
            } catch {
                errorMessage = describeError(error)
                statusMessage = ""
                isLoading = false
            }
        }
    }

    private func submitTwoFA() {
        guard let session = loginSession, !twoFACode.isEmpty else { return }
        isLoading = true
        errorMessage = ""
        statusMessage = "Verifying 2FA code..."

        Task {
            do {
                let ok = try await session.submit2fa(code: twoFACode)
                if ok {
                    await finishLogin(session: session)
                } else {
                    errorMessage = "2FA verification failed. Check the code and try again."
                    statusMessage = ""
                    twoFACode = ""
                    isLoading = false
                }
            } catch {
                errorMessage = describeError(error)
                statusMessage = ""
                isLoading = false
            }
        }
    }

    private func finishLogin(session: LoginSession) async {
        do {
            guard let config = appState.config else { return }
            statusMessage = "Getting IDS authorization..."
            let users = try await session.finish(config: config)
            appState.users = users
            statusMessage = ""
            isLoading = false
            appState.navigateToDevices()
        } catch {
            errorMessage = describeError(error)
            statusMessage = ""
            isLoading = false
        }
    }
}
