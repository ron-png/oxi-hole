use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

const VERSION: &str = env!("OXIDNS_VERSION");
const REPO_OWNER: &str = "ron-png";
const REPO_NAME: &str = "oxi-dns";
pub const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(8 * 60 * 60); // 8 hours

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_url: Option<String>,
    pub download_url: Option<String>,
    pub last_checked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct UpdateStatus {
    pub state: UpdateState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_secs: Option<u64>,
    #[serde(skip)]
    pub last_attempt: Option<std::time::Instant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    #[default]
    Idle,
    Checking,
    Downloading,
    HealthChecking,
    Restarting,
    Failed,
}

impl UpdateStatus {
    pub fn to_serializable(&self) -> UpdateStatus {
        let mut s = self.clone();
        s.last_attempt_secs = s.last_attempt.map(|i| i.elapsed().as_secs());
        s
    }
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Clone)]
pub struct UpdateChecker {
    inner: Arc<RwLock<UpdateCheckerInner>>,
}

struct UpdateCheckerInner {
    cached: Option<VersionInfo>,
    last_check: Option<std::time::Instant>,
}

impl UpdateChecker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(UpdateCheckerInner {
                cached: None,
                last_check: None,
            })),
        }
    }

    /// Return cached version info if still fresh, otherwise fetch from GitHub.
    pub async fn check(&self, force: bool, channel: &str) -> VersionInfo {
        {
            let inner = self.inner.read().await;
            if !force {
                if let (Some(ref cached), Some(last)) = (&inner.cached, inner.last_check) {
                    if last.elapsed() < CHECK_INTERVAL {
                        return cached.clone();
                    }
                }
            }
        }

        let now = Utc::now().to_rfc3339();
        let info = match fetch_latest_release(channel).await {
            Ok(release) => {
                let latest = clean_version(&release.tag_name);
                let update_available = version_newer(&latest, VERSION);
                let download_url = pick_download_asset(&release.assets);
                VersionInfo {
                    current_version: VERSION.to_string(),
                    latest_version: Some(latest),
                    update_available,
                    release_url: Some(release.html_url),
                    download_url,
                    last_checked_at: Some(now),
                }
            }
            Err(e) => {
                warn!("Failed to check for updates: {}", e);
                VersionInfo {
                    current_version: VERSION.to_string(),
                    latest_version: None,
                    update_available: false,
                    release_url: None,
                    download_url: None,
                    last_checked_at: Some(now),
                }
            }
        };

        let mut inner = self.inner.write().await;
        inner.cached = Some(info.clone());
        inner.last_check = Some(std::time::Instant::now());
        info
    }

    /// Download the new binary to a temp path without replacing the current binary.
    /// Returns (temp_path, version_string) on success.
    pub async fn download_update(
        &self,
        channel: &str,
    ) -> Result<(std::path::PathBuf, String), String> {
        let info = self.check(true, channel).await;
        let download_url = info
            .download_url
            .ok_or("No download URL available for this platform")?;
        let latest = info.latest_version.ok_or("Latest version unknown")?;

        info!("Auto-update: downloading v{} from {}", latest, download_url);

        let bytes = reqwest::get(&download_url)
            .await
            .map_err(|e| format!("Download failed: {}", e))?
            .error_for_status()
            .map_err(|e| format!("Download failed: {}", e))?
            .bytes()
            .await
            .map_err(|e| format!("Failed to read download: {}", e))?;

        let binary_bytes = extract_binary_from_tar_gz(&bytes)
            .map_err(|e| format!("Failed to extract update archive: {}", e))?;

        let tmp_path = std::env::temp_dir().join("oxi-dns-update");
        std::fs::write(&tmp_path, &binary_bytes)
            .map_err(|e| format!("Failed to write to temp location: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("Failed to set permissions: {}", e))?;
        }

        Ok((tmp_path, latest))
    }
}

/// Perform a robust update: download → health check → replace → zero-downtime takeover.
/// Updates `update_status` at each stage. On success, calls `std::process::exit(0)` to
/// hand off to the new process. On failure, sets status to Failed and returns.
pub async fn perform_robust_update(
    update_checker: &UpdateChecker,
    update_status: &Arc<RwLock<UpdateStatus>>,
    config_path: &Path,
    current_exe: &Path,
    channel: &str,
) {
    // === Check ===
    info!("Update: checking for updates...");
    {
        let mut s = update_status.write().await;
        s.state = UpdateState::Checking;
        s.message = None;
        s.logs = None;
        s.last_attempt = Some(std::time::Instant::now());
    }

    let info = update_checker.check(true, channel).await;
    if !info.update_available {
        let mut s = update_status.write().await;
        s.state = UpdateState::Idle;
        s.message = Some("No update available".to_string());
        return;
    }

    let latest_version = match info.latest_version {
        Some(v) => v,
        None => {
            let mut s = update_status.write().await;
            s.state = UpdateState::Idle;
            return;
        }
    };

    // === Download ===
    info!("Update: v{} available, downloading...", latest_version);
    {
        let mut s = update_status.write().await;
        s.state = UpdateState::Downloading;
    }

    let (tmp_path, version) = match update_checker.download_update(channel).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Update: download failed: {}", e);
            let mut s = update_status.write().await;
            s.state = UpdateState::Failed;
            s.message = Some(format!("Download failed: {}", e));
            return;
        }
    };

    // === Health check ===
    info!("Update: running health check on v{}...", version);
    {
        let mut s = update_status.write().await;
        s.state = UpdateState::HealthChecking;
    }

    let mut health_child = match tokio::process::Command::new(&tmp_path)
        .arg("--health-check")
        .arg(config_path.to_str().unwrap_or("config.toml"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            warn!("Update: health check failed to run: {}", e);
            let mut s = update_status.write().await;
            s.state = UpdateState::Failed;
            s.message = Some(format!("Health check failed to run: {}", e));
            s.logs = Some(e.to_string());
            return;
        }
    };

    let health_output = tokio::select! {
        result = health_child.wait() => {
            match result {
                Ok(exit_status) => {
                    let mut stdout = Vec::new();
                    let mut stderr = Vec::new();
                    if let Some(mut out) = health_child.stdout.take() {
                        let _ = tokio::io::AsyncReadExt::read_to_end(&mut out, &mut stdout).await;
                    }
                    if let Some(mut err) = health_child.stderr.take() {
                        let _ = tokio::io::AsyncReadExt::read_to_end(&mut err, &mut stderr).await;
                    }
                    std::process::Output { status: exit_status, stdout, stderr }
                }
                Err(e) => {
                    warn!("Update: health check failed: {}", e);
                    let mut s = update_status.write().await;
                    s.state = UpdateState::Failed;
                    s.message = Some(format!("Health check failed: {}", e));
                    s.logs = Some(e.to_string());
                    return;
                }
            }
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
            warn!("Update: health check timed out (30s), killing child process");
            let _ = health_child.kill().await;
            let mut s = update_status.write().await;
            s.state = UpdateState::Failed;
            s.message = Some("Health check timed out after 30 seconds".to_string());
            return;
        }
    };

    let health_logs = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&health_output.stdout),
        String::from_utf8_lossy(&health_output.stderr)
    );

    if !health_output.status.success() {
        warn!(
            "Update: health check failed (exit code {:?})",
            health_output.status.code()
        );
        let mut s = update_status.write().await;
        s.state = UpdateState::Failed;
        s.message = Some(format!(
            "Health check failed with exit code {}",
            health_output.status.code().unwrap_or(-1)
        ));
        s.logs = Some(health_logs);
        return;
    }

    // === Replace binary ===
    info!("Update: health check passed, replacing binary...");

    let binary_bytes = match std::fs::read(&tmp_path) {
        Ok(b) => b,
        Err(e) => {
            let mut s = update_status.write().await;
            s.state = UpdateState::Failed;
            s.message = Some(format!("Failed to read temp binary: {}", e));
            return;
        }
    };

    if let Err(e) = try_replace_binary(current_exe, &binary_bytes) {
        let mut s = update_status.write().await;
        s.state = UpdateState::Failed;
        s.message = Some(format!("Failed to replace binary: {}", e));
        return;
    }

    let _ = std::fs::remove_file(&tmp_path);

    // === Takeover restart ===
    info!("Update: starting v{} with --takeover...", version);
    {
        let mut s = update_status.write().await;
        s.state = UpdateState::Restarting;
    }

    let ready_path = std::env::temp_dir().join("oxi-dns.ready");
    let _ = std::fs::remove_file(&ready_path);

    let mut child = match tokio::process::Command::new(current_exe)
        .arg("--takeover")
        .arg("--ready-file")
        .arg(ready_path.to_str().unwrap())
        .arg(config_path.to_str().unwrap_or("config.toml"))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Update: failed to start new process: {}", e);
            let mut s = update_status.write().await;
            s.state = UpdateState::Failed;
            s.message = Some(format!("Failed to start new process: {}", e));
            return;
        }
    };

    // Wait for ready file (poll every 500ms, up to 60s)
    let mut ready = false;
    for _ in 0..120 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        match child.try_wait() {
            Ok(Some(status)) => {
                warn!("Update: new process exited early with {:?}", status);
                let mut s = update_status.write().await;
                s.state = UpdateState::Failed;
                s.message = Some(format!("New process exited with {:?}", status));
                break;
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Update: failed to check child: {}", e);
                break;
            }
        }

        if ready_path.exists() {
            ready = true;
            break;
        }
    }

    if ready {
        warn!("Update: v{} is ready, handing off — goodbye!", version);
        let _ = std::fs::remove_file(&ready_path);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        std::process::exit(0);
    } else {
        warn!("Update: new process failed to become ready within 60s");
        let _ = child.kill().await;
        let mut s = update_status.write().await;
        if s.state != UpdateState::Failed {
            s.state = UpdateState::Failed;
            s.message = Some("New process failed to become ready within 60 seconds".to_string());
        }
    }
}

/// Try to backup and replace the binary in-place.
/// On Linux, a running binary can't be written to (ETXTBSY), but it CAN be
/// deleted — the running process keeps its file handle. We unlink first,
/// then write the new binary to the same path.
pub fn try_replace_binary(
    current_exe: &std::path::Path,
    binary_bytes: &[u8],
) -> Result<(), std::io::Error> {
    let backup = current_exe.with_extension("bak");
    std::fs::copy(current_exe, &backup)?;
    // Remove the old binary (running process keeps its inode alive)
    std::fs::remove_file(current_exe)?;
    // Write new binary to the now-free path
    std::fs::write(current_exe, binary_bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(current_exe, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(())
}

/// Extract the binary from a .tar.gz archive. Looks for the first regular file entry.
fn extract_binary_from_tar_gz(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let gz = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(gz);

    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if entry.header().entry_type().is_file() {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| e.to_string())?;
            return Ok(buf);
        }
    }

    Err("No file found in archive".to_string())
}

async fn fetch_latest_release(channel: &str) -> anyhow::Result<GitHubRelease> {
    if channel == "development" {
        let url = format!(
            "https://api.github.com/repos/{}/{}/releases",
            REPO_OWNER, REPO_NAME
        );
        let client = reqwest::Client::new();
        let releases: Vec<GitHubRelease> = client
            .get(&url)
            .header("User-Agent", format!("oxi-dns/{}", VERSION))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        // Pick the release with the highest version (GitHub order is by creation date, not version)
        releases
            .into_iter()
            .max_by(|a, b| {
                let va = clean_version(&a.tag_name);
                let vb = clean_version(&b.tag_name);
                let (a_nums, a_suf) = parse_version(&va);
                let (b_nums, b_suf) = parse_version(&vb);
                a_nums.cmp(&b_nums).then(a_suf.cmp(&b_suf))
            })
            .ok_or_else(|| anyhow::anyhow!("No releases found"))
    } else {
        let url = format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            REPO_OWNER, REPO_NAME
        );
        let client = reqwest::Client::new();
        let release: GitHubRelease = client
            .get(&url)
            .header("User-Agent", format!("oxi-dns/{}", VERSION))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(release)
    }
}

/// Extract version from a release tag, stripping prefix and non-version suffixes.
/// e.g. "v0.0.5b---docker" -> "0.0.5b", "v0.0.4a" -> "0.0.4a"
fn clean_version(tag: &str) -> String {
    let s = tag.trim_start_matches('v');
    // Take the version part: digits, dots, and trailing letters (e.g. "0.0.5b")
    // Stop at the first '-' or any other non-version character
    s.split('-').next().unwrap_or(s).to_string()
}

/// Parse a version string like "0.0.5b" into numeric parts and an optional letter suffix.
fn parse_version(v: &str) -> (Vec<u64>, Option<char>) {
    let v = v.trim_start_matches('v');
    let mut nums = Vec::new();
    let mut suffix = None;

    for part in v.split('.') {
        // Last segment may have a letter suffix, e.g. "5b"
        let num_str: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        let letter: Option<char> = part.chars().find(|c| c.is_ascii_alphabetic());
        if let Ok(n) = num_str.parse::<u64>() {
            nums.push(n);
        }
        if letter.is_some() {
            suffix = letter;
        }
    }
    (nums, suffix)
}

/// Returns true if `latest` is newer than `current`.
/// Handles versions like "0.0.5b" > "0.0.5a" > "0.0.5" > "0.0.4a".
fn version_newer(latest: &str, current: &str) -> bool {
    let (l_nums, l_suf) = parse_version(latest);
    let (c_nums, c_suf) = parse_version(current);
    match l_nums.cmp(&c_nums) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => l_suf > c_suf,
    }
}

/// Pick the right binary asset for the current OS/arch.
fn pick_download_asset(assets: &[GitHubAsset]) -> Option<String> {
    let os = std::env::consts::OS; // "linux", "macos", "windows"
    let arch = std::env::consts::ARCH; // "x86_64", "aarch64", etc.

    // Map Rust arch names to common release naming
    let arch_patterns: Vec<&str> = match arch {
        "x86_64" => vec!["x86_64", "amd64"],
        "aarch64" => vec!["aarch64", "arm64"],
        "arm" => vec!["armv7", "armhf", "arm"],
        other => vec![other],
    };

    for asset in assets {
        let name = asset.name.to_lowercase();
        let os_match = name.contains(os);
        let arch_match = arch_patterns.iter().any(|p| name.contains(p));
        if os_match && arch_match {
            return Some(asset.browser_download_url.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_newer() {
        assert!(version_newer("0.4.0", "0.3.0"));
        assert!(version_newer("0.3.1", "0.3.0"));
        assert!(version_newer("1.0.0", "0.9.9"));
        assert!(!version_newer("0.3.0", "0.3.0"));
        assert!(!version_newer("0.2.0", "0.3.0"));
        // Letter suffixes
        assert!(version_newer("0.0.5b", "0.0.5a"));
        assert!(version_newer("0.0.5a", "0.0.5"));
        assert!(version_newer("0.0.5b", "0.0.5"));
        assert!(!version_newer("0.0.5a", "0.0.5a"));
        assert!(!version_newer("0.0.5", "0.0.5a"));
        assert!(version_newer("0.0.6", "0.0.5b"));
        // 4-part versions
        assert!(version_newer("0.4.0.4", "0.4.0"));
        assert!(version_newer("0.4.0.6", "0.4.0.4"));
        assert!(!version_newer("0.4.0.4", "0.4.0.4"));
        assert!(!version_newer("0.4.0.3", "0.4.0.4"));
        // Multi-digit version parts (10+, 100+)
        assert!(version_newer("0.4.0.10", "0.4.0.9"));
        assert!(version_newer("0.4.0.100", "0.4.0.99"));
        assert!(version_newer("0.4.0.111", "0.4.0.110"));
        assert!(version_newer("0.4.10", "0.4.9"));
        assert!(version_newer("0.4.100", "0.4.99"));
        assert!(version_newer("0.4.111", "0.4.110"));
        // Ensure numeric, not lexicographic (10 > 9, not "10" < "9")
        assert!(version_newer("0.4.0.10", "0.4.0.2"));
        assert!(version_newer("0.4.10", "0.4.2"));
        assert!(version_newer("0.4.0.15", "0.4.0.9"));
        assert!(version_newer("0.4.0.15", "0.4.0.14"));
        assert!(!version_newer("0.4.0.9", "0.4.0.15"));
        assert!(!version_newer("0.4.0.15", "0.4.0.15"));
    }

    #[test]
    fn test_clean_version() {
        assert_eq!(clean_version("v0.0.5b---docker"), "0.0.5b");
        assert_eq!(clean_version("v0.0.4a"), "0.0.4a");
        assert_eq!(clean_version("v1.2.3"), "1.2.3");
        assert_eq!(clean_version("0.0.5"), "0.0.5");
        // Dev suffix stripped
        assert_eq!(clean_version("v0.4.0.6-dev"), "0.4.0.6");
        assert_eq!(clean_version("v0.4.0.4-dev"), "0.4.0.4");
    }
}
