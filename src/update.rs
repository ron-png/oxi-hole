use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

const VERSION: &str = env!("OXIHOLE_VERSION");
const REPO_OWNER: &str = "ron-png";
const REPO_NAME: &str = "oxi-hole";
const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(8 * 60 * 60); // 8 hours

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_url: Option<String>,
    pub download_url: Option<String>,
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
    pub async fn check(&self, force: bool) -> VersionInfo {
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

        let info = match fetch_latest_release().await {
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
                }
            }
        };

        let mut inner = self.inner.write().await;
        inner.cached = Some(info.clone());
        inner.last_check = Some(std::time::Instant::now());
        info
    }

    /// Download the new binary and replace the current one, then restart.
    pub async fn perform_update(&self) -> Result<String, String> {
        let info = self.check(false).await;
        let download_url = info
            .download_url
            .ok_or("No download URL available for this platform")?;
        let latest = info.latest_version.ok_or("Latest version unknown")?;

        info!("Downloading update v{} from {}", latest, download_url);

        // The release assets are .tar.gz archives containing the binary
        let bytes = reqwest::get(&download_url)
            .await
            .map_err(|e| format!("Download failed: {}", e))?
            .error_for_status()
            .map_err(|e| format!("Download failed: {}", e))?
            .bytes()
            .await
            .map_err(|e| format!("Failed to read download: {}", e))?;

        // Extract binary from tar.gz archive
        let binary_bytes = extract_binary_from_tar_gz(&bytes)
            .map_err(|e| format!("Failed to extract update archive: {}", e))?;

        let current_exe =
            std::env::current_exe().map_err(|e| format!("Cannot find current binary: {}", e))?;

        // Try direct replacement first
        if let Err(direct_err) = try_replace_binary(&current_exe, &binary_bytes) {
            // Direct write failed — try writing to /tmp and replacing via rename
            let tmp_path = std::path::PathBuf::from("/tmp/oxi-hole.update");
            std::fs::write(&tmp_path, &binary_bytes)
                .map_err(|e| format!("Failed to write to temp location: {}", e))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| format!("Failed to set permissions: {}", e))?;
            }

            // Try rename (only works on same filesystem)
            if std::fs::rename(&tmp_path, &current_exe).is_err() {
                // Different filesystem or read-only — leave in /tmp for manual install
                return Err(format!(
                    "Cannot write to {} ({}). New v{} binary saved to {}. \
                     Install manually: sudo cp {} {}",
                    current_exe.display(),
                    direct_err,
                    latest,
                    tmp_path.display(),
                    tmp_path.display(),
                    current_exe.display()
                ));
            }
        }

        info!(
            "Update to v{} complete. Restart the service to apply.",
            latest
        );
        Ok(format!("Updated to v{}. Restart to apply.", latest))
    }
}

/// Try to backup and replace the binary in-place.
/// On Linux, a running binary can't be written to (ETXTBSY), but it CAN be
/// deleted — the running process keeps its file handle. We unlink first,
/// then write the new binary to the same path.
fn try_replace_binary(
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

async fn fetch_latest_release() -> anyhow::Result<GitHubRelease> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        REPO_OWNER, REPO_NAME
    );
    let client = reqwest::Client::new();
    let release: GitHubRelease = client
        .get(&url)
        .header("User-Agent", format!("oxi-hole/{}", VERSION))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(release)
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
    }

    #[test]
    fn test_clean_version() {
        assert_eq!(clean_version("v0.0.5b---docker"), "0.0.5b");
        assert_eq!(clean_version("v0.0.4a"), "0.0.4a");
        assert_eq!(clean_version("v1.2.3"), "1.2.3");
        assert_eq!(clean_version("0.0.5"), "0.0.5");
    }
}
