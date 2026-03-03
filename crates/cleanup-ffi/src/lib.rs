//! cleanup-ffi — uniffi bindings for the iMessage device cleanup tool.
//!
//! This crate exposes a minimal subset of rustpush's IDS protocol to Swift:
//! 1. Hardware config (IOKit) — needed because Apple validates HW identity during auth
//! 2. APS push connection — required for all IDS API calls (push tokens = device IDs)
//! 3. Apple ID login with 2FA — authenticates against Apple's GSA/IDS servers
//! 4. Device listing — calls get_dependent_registrations() to see all registered devices
//! 5. Device deregistration — removes ghost devices (experimental)
//!
//! IMPORTANT: This tool deliberately does NOT call register(), so it never creates
//! a new ghost device. It only authenticates (for API access) and lists/deletes.

pub mod local_config;
mod util;

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use icloud_auth::AppleAccount;
use keystore::{init_keystore, software::{NoEncryptor, SoftwareKeystore, SoftwareKeystoreState}};
use log::{error, info, warn};
use omnisette::default_provider;
use rustpush::{
    authenticate_apple, login_apple_delegates,
    APSConnectionResource, APSState, IDSUser,
    LoginDelegate, OSConfig,
};
use std::sync::RwLock;
use util::plist_from_string;

// ============================================================================
// Error type
// ============================================================================

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum CleanupError {
    #[error("{msg}")]
    Generic { msg: String },
}

impl From<rustpush::PushError> for CleanupError {
    fn from(e: rustpush::PushError) -> Self {
        CleanupError::Generic { msg: format!("{}", e) }
    }
}

// ============================================================================
// Wrapped types
// ============================================================================

/// APS push connection state — contains the push token and keypair.
#[derive(uniffi::Object)]
pub struct WrappedAPSState {
    inner: Option<APSState>,
}

#[uniffi::export]
impl WrappedAPSState {
    #[uniffi::constructor]
    pub fn new(string: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            inner: string
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .and_then(|s| plist_from_string::<APSState>(&s).ok()),
        })
    }
}

/// Live APS push connection. All IDS API calls need this because Apple
/// uses the push token to identify which device is making the request.
#[derive(uniffi::Object)]
pub struct WrappedAPSConnection {
    inner: rustpush::APSConnection,
}

#[uniffi::export]
impl WrappedAPSConnection {
    /// Get our push token as hex. Compare against DeviceInfo.token_hex
    /// to identify which device in the list is "us" (the cleanup tool).
    /// Since we don't register, this token won't appear in the device list —
    /// but active bridge instances sharing our hardware WILL appear.
    pub fn get_token_hex(&self) -> String {
        let state = self.inner.state.blocking_read();
        state.token
            .map(|t| t.iter().map(|b| format!("{:02x}", b)).collect())
            .unwrap_or_default()
    }
}

/// Hardware identity provider. Apple requires real HW identifiers
/// (serial, UUID, ROM, MLB) for IDS auth and NAC validation.
#[derive(uniffi::Object)]
pub struct WrappedOSConfig {
    config: Arc<dyn OSConfig>,
}

/// Authenticated IDS user — has auth keypairs for signing API requests.
/// We get this from authenticate_apple() WITHOUT calling register(),
/// so we never create a new device entry.
#[derive(uniffi::Object)]
pub struct WrappedIDSUsers {
    /// Mutable because re-authentication overwrites the keystore entry,
    /// so we need to update this after each delete cycle.
    inner: tokio::sync::RwLock<Vec<IDSUser>>,
    /// Saved login credentials for re-authentication.
    /// Each call to login_apple_delegates + authenticate_apple generates a fresh RSA keypair,
    /// which is needed to make approach N work for multiple devices.
    username: String,
    pet: String,
    adsid: String,
}

// ============================================================================
// Device info record — what we show in the UI
// ============================================================================

/// A registered iMessage device as returned by Apple's IDS servers.
/// Ghost devices are bridge sessions that were lost but never deregistered.
#[derive(uniffi::Record, Clone)]
pub struct DeviceInfo {
    /// Device name (e.g. "Mac-C02XX..." for bridge, "David's iPhone" for real)
    pub device_name: String,
    /// Device UUID from private-device-data
    pub uuid: String,
    /// Push token as hex — unique device identifier
    pub token_hex: String,
    /// Push token as base64 — needed for deregistration API calls
    pub token_base64: String,
    /// Whether this device is HSA-trusted (two-step auth)
    pub is_hsa_trusted: bool,
    /// Registration timestamp as Unix epoch seconds.
    /// Derived from private-device-data "d" field (Apple epoch + 978307200).
    /// 0 if not available.
    pub registered_epoch: f64,
    /// Registered handles (e.g. ["mailto:user@icloud.com", "tel:+1234567890"])
    pub identities: Vec<String>,
    /// Sub-services (e.g. ["com.apple.private.alloy.sms"])
    pub sub_services: Vec<String>,
}

// ============================================================================
// Top-level functions
// ============================================================================

/// Initialize logging and the software keystore. Call once at app startup.
/// Uses a separate keystore from the bridge so they don't interfere.
#[uniffi::export]
pub fn init_cleanup() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    let _ = pretty_env_logger::try_init();

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let state_dir = format!("{}/.local/share/imessage-cleanup", home);
    let _ = std::fs::create_dir_all(&state_dir);
    let state_path = format!("{}/keystore.plist", state_dir);

    let state: SoftwareKeystoreState = match std::fs::read(&state_path) {
        Ok(data) => plist::from_bytes(&data).unwrap_or_else(|e| {
            warn!("Failed to parse keystore at {}: {} — starting fresh", state_path, e);
            SoftwareKeystoreState::default()
        }),
        Err(_) => {
            info!("No keystore at {} — starting fresh", state_path);
            SoftwareKeystoreState::default()
        }
    };
    let path_for_closure = state_path.clone();
    init_keystore(SoftwareKeystore {
        state: RwLock::new(state),
        update_state: Box::new(move |s| {
            let _ = plist::to_file_xml(&path_for_closure, s);
        }),
        encryptor: NoEncryptor,
    });
}

/// Read hardware identifiers from IOKit and create the OS config.
/// macOS-only (the cleanup tool is macOS-only since it needs NAC).
#[uniffi::export]
pub fn create_config() -> Result<Arc<WrappedOSConfig>, CleanupError> {
    let config = local_config::LocalMacOSConfig::new()
        .map_err(|e| CleanupError::Generic { msg: format!("Failed to read hardware info: {}", e) })?;
    Ok(Arc::new(WrappedOSConfig {
        config: Arc::new(config),
    }))
}

/// Connect to Apple Push Notification service.
/// Establishes a persistent connection and obtains a push token.
#[uniffi::export(async_runtime = "tokio")]
pub async fn connect(
    config: &WrappedOSConfig,
    state: &WrappedAPSState,
) -> Arc<WrappedAPSConnection> {
    let config = config.config.clone();
    let state = state.inner.clone();
    let (connection, error) = APSConnectionResource::new(config, state).await;
    if let Some(error) = error {
        error!("APS connection error (non-fatal, will retry): {}", error);
    }
    Arc::new(WrappedAPSConnection { inner: connection })
}

// ============================================================================
// Login flow — start → 2FA → finish
//
// Apple's auth is multi-step:
// 1. SRP auth with hashed password
// 2. Optional 2FA verification
// 3. IDS delegate authentication (gives us auth keypairs for API signing)
//
// We deliberately skip register() so the cleanup tool never creates a device.
// authenticate_apple() alone gives us the auth keypairs needed for
// get_dependent_registrations() — no registration required.
// ============================================================================

/// Login session state between auth steps.
#[derive(uniffi::Object)]
pub struct LoginSession {
    account: tokio::sync::Mutex<Option<AppleAccount<omnisette::DefaultAnisetteProvider>>>,
    username: String,
    #[allow(dead_code)]
    password_hash: Vec<u8>,
    needs_2fa: bool,
}

/// Start login: authenticate with Apple ID + password via SRP.
#[uniffi::export(async_runtime = "tokio")]
pub async fn login_start(
    apple_id: String,
    password: String,
    config: &WrappedOSConfig,
    connection: &WrappedAPSConnection,
) -> Result<Arc<LoginSession>, CleanupError> {
    let os_config = config.config.clone();
    let conn = connection.inner.clone();

    let user_trimmed = apple_id.trim().to_string();
    let pw_bytes = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(password.trim().as_bytes());
        hasher.finalize().to_vec()
    };

    let client_info = os_config.get_gsa_config(&*conn.state.read().await, false);
    let anisette = default_provider(client_info.clone(), PathBuf::from_str("state/anisette").unwrap());

    let mut account = AppleAccount::new_with_anisette(client_info, anisette)
        .map_err(|e| CleanupError::Generic { msg: format!("Failed to create account: {}", e) })?;

    let result = account.login_email_pass(&user_trimmed, &pw_bytes).await
        .map_err(|e| CleanupError::Generic { msg: format!("Login failed: {}", e) })?;

    info!("login_email_pass returned: {:?}", result);
    let needs_2fa = match result {
        icloud_auth::LoginState::LoggedIn => false,
        icloud_auth::LoginState::Needs2FAVerification => true,
        icloud_auth::LoginState::NeedsDevice2FA | icloud_auth::LoginState::NeedsSMS2FA => {
            match account.send_2fa_to_devices().await {
                Ok(_) => info!("Sent 2FA push to trusted devices"),
                Err(e) => error!("Failed to send 2FA push: {}", e),
            }
            true
        }
        icloud_auth::LoginState::NeedsSMS2FAVerification(_) => true,
        icloud_auth::LoginState::NeedsExtraStep(ref step) => {
            if account.get_pet().is_some() {
                false
            } else {
                return Err(CleanupError::Generic { msg: format!("Login requires extra step: {}", step) });
            }
        }
        icloud_auth::LoginState::NeedsLogin => {
            return Err(CleanupError::Generic { msg: "Login failed — bad credentials".into() });
        }
    };

    Ok(Arc::new(LoginSession {
        account: tokio::sync::Mutex::new(Some(account)),
        username: user_trimmed,
        password_hash: pw_bytes,
        needs_2fa,
    }))
}

#[uniffi::export(async_runtime = "tokio")]
impl LoginSession {
    pub fn needs_2fa(&self) -> bool {
        self.needs_2fa
    }

    /// Submit 6-digit 2FA code. Returns true if verification succeeded.
    pub async fn submit_2fa(&self, code: String) -> Result<bool, CleanupError> {
        let mut guard = self.account.lock().await;
        let account = guard.as_mut()
            .ok_or(CleanupError::Generic { msg: "No active session".into() })?;

        let result = account.verify_2fa(code).await
            .map_err(|e| CleanupError::Generic { msg: format!("2FA failed: {}", e) })?;

        info!("2FA result: {:?}, PET available: {}", result, account.get_pet().is_some());
        match result {
            icloud_auth::LoginState::LoggedIn => Ok(true),
            icloud_auth::LoginState::NeedsExtraStep(_) => Ok(account.get_pet().is_some()),
            _ => Ok(false),
        }
    }

    /// Complete login: get IDS delegate and authenticate.
    /// This gives us auth keypairs for API calls WITHOUT registering a device.
    /// The cleanup tool will NOT appear as a new device in Text Message Forwarding.
    pub async fn finish(
        &self,
        config: &WrappedOSConfig,
    ) -> Result<Arc<WrappedIDSUsers>, CleanupError> {
        let os_config = config.config.clone();

        let mut guard = self.account.lock().await;
        let account = guard.as_mut()
            .ok_or(CleanupError::Generic { msg: "No active session".into() })?;

        let pet = account.get_pet()
            .ok_or(CleanupError::Generic { msg: "No PET token after login".into() })?;

        let spd = account.spd.as_ref().expect("No SPD after login");
        let adsid = spd.get("adsid").expect("No adsid").as_string().unwrap().to_string();

        let delegates = login_apple_delegates(
            &self.username,
            &pet,
            &adsid,
            None,
            &mut *account.anisette.lock().await,
            &*os_config,
            &[LoginDelegate::IDS],
        ).await.map_err(|e| CleanupError::Generic { msg: format!("Failed to get delegates: {}", e) })?;

        let ids_delegate = delegates.ids
            .ok_or(CleanupError::Generic { msg: "No IDS delegate in response".into() })?;

        // authenticate_apple() gives us auth keypairs for signing IDS API requests.
        // This does NOT register a device — it only gets an auth certificate.
        let user = authenticate_apple(ids_delegate, &*os_config).await
            .map_err(|e| CleanupError::Generic { msg: format!("IDS auth failed: {}", e) })?;

        info!("Login complete — authenticated as {} (no device registered)", user.user_id);

        Ok(Arc::new(WrappedIDSUsers {
            inner: tokio::sync::RwLock::new(vec![user]),
            username: self.username.clone(),
            pet: pet.to_string(),
            adsid: adsid.to_string(),
        }))
    }
}

// ============================================================================
// Device listing
// ============================================================================

/// Fetch all iMessage devices registered under this Apple ID.
/// Returns every device in iOS Settings → Messages → Text Message Forwarding.
///
/// To identify device types:
/// - Bridge ghosts typically have names like "Mac-XXXXXX" (the bridge's default name format)
/// - Real Apple devices have user-assigned names like "David's iPhone"
/// - Active bridge instances can be identified by checking if their push token
///   matches a currently-running bridge's token
#[uniffi::export(async_runtime = "tokio")]
pub async fn get_devices(
    users: &WrappedIDSUsers,
    connection: &WrappedAPSConnection,
) -> Result<Vec<DeviceInfo>, CleanupError> {
    let users_guard = users.inner.read().await;
    if users_guard.is_empty() {
        return Err(CleanupError::Generic { msg: "No authenticated users".into() });
    }

    let aps_state = connection.inner.state.read().await;

    let raw = users_guard[0].get_dependent_registrations_raw(&aps_state).await?;
    let parsed: plist::Value = plist::from_bytes(&raw)
        .map_err(|e| CleanupError::Generic { msg: format!("Failed to parse plist: {}", e) })?;
    let dict = parsed.as_dictionary()
        .ok_or(CleanupError::Generic { msg: "Response is not a dictionary".into() })?;
    let status = dict.get("status")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(0);
    if status != 0 {
        return Err(CleanupError::Generic { msg: format!("Apple returned status {}", status) });
    }
    let registrations = dict.get("registrations")
        .and_then(|v| v.as_array())
        .ok_or(CleanupError::Generic { msg: "No registrations array in response".into() })?;

    Ok(registrations.iter().filter_map(|dev| {
        let d = dev.as_dictionary()?;
        if d.get("service")?.as_string()? != "com.apple.madrid" {
            return None;
        }
        let token = d.get("push-token")?.as_data()?.to_vec();
        let token_hex: String = token.iter().map(|b| format!("{:02x}", b)).collect();
        let token_base64 = BASE64_STANDARD.encode(&token);
        Some(DeviceInfo {
            device_name: d.get("device-name").and_then(|v| v.as_string()).unwrap_or("Unknown").to_string(),
            uuid: d.get("private-device-data")
                .and_then(|v| v.as_dictionary())
                .and_then(|pd| pd.get("u"))
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string(),
            token_hex,
            token_base64,
            is_hsa_trusted: d.get("is-hsa-trusted-device").and_then(|v| v.as_boolean()).unwrap_or(false),
            registered_epoch: d.get("private-device-data")
                .and_then(|v| v.as_dictionary())
                .and_then(|pd| pd.get("d"))
                .and_then(|v| v.as_string())
                .and_then(|s| s.parse::<f64>().ok())
                .map(|apple_epoch| apple_epoch + 978307200.0) // Apple epoch → Unix epoch
                .unwrap_or(0.0),
            identities: d.get("identities")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|id| {
                    id.as_dictionary()?.get("uri")?.as_string().map(|s| s.to_string())
                }).collect())
                .unwrap_or_default(),
            sub_services: d.get("sub-services")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_string().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
        })
    }).collect())
}

// ============================================================================
// Deregistration (experimental)
// ============================================================================

/// Deregister a single device by its push token.
/// Tries multiple signing/format approaches and returns the best IDS status code.
/// Status 0 = likely success. Refresh device list to verify.
#[uniffi::export(async_runtime = "tokio")]
pub async fn deregister_device(
    users: &WrappedIDSUsers,
    connection: &WrappedAPSConnection,
    config: &WrappedOSConfig,
    target_token_base64: String,
) -> Result<u64, CleanupError> {
    let users_guard = users.inner.read().await;
    if users_guard.is_empty() {
        return Err(CleanupError::Generic { msg: "No authenticated users".into() });
    }

    let token_bytes = BASE64_STANDARD.decode(&target_token_base64)
        .map_err(|e| CleanupError::Generic { msg: format!("Invalid token base64: {}", e) })?;

    let aps_state = connection.inner.state.read().await;
    let user = &users_guard[0];

    let status = user.deregister_device(&aps_state, &*config.config, &token_bytes).await?;
    info!("deregister_device returned status {} for token {}", status, &target_token_base64[..16.min(target_token_base64.len())]);
    Ok(status)
}

/// Delete a single device. For each call:
/// 1. Create a TEMP APS connection (new push token, same keypair — no keystore overwrite)
/// 2. Re-authenticate to get a fresh auth keypair
/// 3. Register on the temp connection → new id_keypair
/// 4. Approach N on the temp connection to deregister target
/// 5. Deregister self on the temp connection
///
/// Apple tracks deregister-other by push token. Same push token = one deregister max.
/// A fresh push token (from the temp connection) bypasses this limit.
#[uniffi::export(async_runtime = "tokio")]
pub async fn register_and_deregister_device(
    users: &WrappedIDSUsers,
    connection: &WrappedAPSConnection,
    config: &WrappedOSConfig,
    target_token_base64: String,
) -> Result<u64, CleanupError> {
    use rustpush::{register, authenticate_apple, login_apple_delegates, IDSNGMIdentity, MADRID_SERVICE, LoginDelegate, APSState};

    {
        let users_guard = users.inner.read().await;
        if users_guard.is_empty() {
            return Err(CleanupError::Generic { msg: "No authenticated users".into() });
        }
    }

    let token_bytes = BASE64_STANDARD.decode(&target_token_base64)
        .map_err(|e| CleanupError::Generic { msg: format!("Invalid token base64: {}", e) })?;

    // Step 1: Create a TEMP APS connection with a NEW push token.
    // Reuse the same push keypair from the main connection (so activate() is skipped
    // and the keystore is NOT overwritten), but set token=None so Apple assigns a fresh one.
    // This is critical: Apple limits deregister-other to one per push token.
    info!("=== Creating temp APS connection for fresh push token ===");
    let existing_keypair = {
        let state = connection.inner.state.read().await;
        state.keypair.clone()
            .ok_or(CleanupError::Generic { msg: "No push keypair on main connection".into() })?
    };
    let temp_state = APSState {
        token: None,  // Force Apple to assign a new push token
        keypair: Some(existing_keypair),
    };
    let (temp_conn, temp_err) = APSConnectionResource::new(
        config.config.clone(),
        Some(temp_state),
    ).await;
    if let Some(e) = temp_err {
        return Err(CleanupError::Generic { msg: format!("Temp APS connection failed: {}", e) });
    }
    info!("=== Temp connection established, got new push token ===");

    // Step 2: Re-authenticate to get a FRESH auth keypair (new RSA key).
    // authenticate_apple() overwrites the keystore entry, so we MUST update
    // the stored user afterwards or get_devices() will fail with 6005.
    info!("=== Re-authenticating for fresh auth keypair ===");
    let os_config = config.config.clone();
    let client_info = os_config.get_gsa_config(&*temp_conn.state.read().await, false);
    let anisette_arc = default_provider(client_info.clone(), PathBuf::from_str("state/anisette").unwrap());

    let delegates = {
        let mut anisette_guard = anisette_arc.lock().await;
        login_apple_delegates(
            &users.username,
            &users.pet,
            &users.adsid,
            None,
            &mut *anisette_guard,
            &*os_config,
            &[LoginDelegate::IDS],
        ).await.map_err(|e| CleanupError::Generic { msg: format!("Re-delegate failed: {}", e) })?
    };

    let ids_delegate = delegates.ids
        .ok_or(CleanupError::Generic { msg: "No IDS delegate in re-auth response".into() })?;

    let fresh_user = authenticate_apple(ids_delegate, &*os_config).await
        .map_err(|e| CleanupError::Generic { msg: format!("Re-auth failed: {}", e) })?;
    let mut fresh_users = vec![fresh_user];

    // Step 3: Register on the TEMP connection to get a new id_keypair
    info!("=== Registering on temp connection ===");
    let identity = IDSNGMIdentity::new()
        .map_err(|e| CleanupError::Generic { msg: format!("Failed to create identity: {}", e) })?;

    {
        let aps_state = temp_conn.state.read().await;
        register(
            &*config.config,
            &aps_state,
            &[&MADRID_SERVICE],
            &mut fresh_users,
            &identity,
        ).await?;
    }

    // Step 4: Approach N on the TEMP connection — deregister target
    info!("=== Deregistering target via approach N (temp connection) ===");
    let status = {
        let aps_state = temp_conn.state.read().await;
        fresh_users[0].deregister_target_n(&aps_state, &*config.config, &token_bytes).await
            .map_err(|e| CleanupError::Generic { msg: format!("Deregister failed: {}", e) })?
    };

    // Step 5: Deregister self on the TEMP connection to clean up
    info!("=== Deregistering self on temp connection ===");
    {
        let aps_state = temp_conn.state.read().await;
        if let Err(e) = fresh_users[0].deregister_self(&aps_state, &*config.config).await {
            warn!("Failed to deregister self after target delete: {}", e);
        }
    }

    // Step 6: Update the stored user with the fresh auth keypair.
    // authenticate_apple() overwrites the RSA key in the keystore, so the old
    // user's auth_keypair cert no longer matches the key.
    {
        let mut users_guard = users.inner.write().await;
        if !users_guard.is_empty() {
            users_guard[0] = fresh_users.remove(0);
        }
    }

    info!("register_and_deregister_device: status {}", status);
    // temp_conn is dropped here — the temp APS connection closes automatically
    Ok(status)
}

/// Deregister the cleanup tool on sign out to avoid leaving a ghost.
///
/// The tool doesn't register during login (to avoid creating ghosts on startup),
/// but after deleting devices the keystore auth key has been overwritten by
/// re-authentication. We must register on the main connection first so there's
/// something to deregister, then deregister self.
#[uniffi::export(async_runtime = "tokio")]
pub async fn cleanup_deregister(
    users: &WrappedIDSUsers,
    connection: &WrappedAPSConnection,
    config: &WrappedOSConfig,
) -> Result<(), CleanupError> {
    use rustpush::{register, authenticate_apple, login_apple_delegates, IDSNGMIdentity, MADRID_SERVICE, LoginDelegate, APSState};

    info!("=== Cleanup deregister (sign out) ===");

    // Re-authenticate to get a fresh user whose auth key matches the keystore
    let os_config = config.config.clone();
    let client_info = os_config.get_gsa_config(&*connection.inner.state.read().await, false);
    let anisette_arc = default_provider(client_info.clone(), PathBuf::from_str("state/anisette").unwrap());

    let delegates = {
        let mut anisette_guard = anisette_arc.lock().await;
        login_apple_delegates(
            &users.username,
            &users.pet,
            &users.adsid,
            None,
            &mut *anisette_guard,
            &*os_config,
            &[LoginDelegate::IDS],
        ).await.map_err(|e| CleanupError::Generic { msg: format!("Sign-out re-auth failed: {}", e) })?
    };

    let ids_delegate = delegates.ids
        .ok_or(CleanupError::Generic { msg: "No IDS delegate for sign-out".into() })?;

    let fresh_user = authenticate_apple(ids_delegate, &*os_config).await
        .map_err(|e| CleanupError::Generic { msg: format!("Sign-out auth failed: {}", e) })?;
    let mut fresh_users = vec![fresh_user];

    // Register on the main connection so we have something to deregister
    let identity = IDSNGMIdentity::new()
        .map_err(|e| CleanupError::Generic { msg: format!("Failed to create identity: {}", e) })?;

    {
        let aps_state = connection.inner.state.read().await;
        register(
            &*config.config,
            &aps_state,
            &[&MADRID_SERVICE],
            &mut fresh_users,
            &identity,
        ).await?;
    }
    info!("Registered on main connection for clean deregister");

    // Now deregister self
    {
        let aps_state = connection.inner.state.read().await;
        if let Err(e) = fresh_users[0].deregister_self(&aps_state, &*config.config).await {
            warn!("Failed to deregister self: {}", e);
        } else {
            info!("Successfully deregistered cleanup tool.");
        }
    }

    Ok(())
}

uniffi::setup_scaffolding!();
