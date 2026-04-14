//! Hardware-adaptive resource limits.
//!
//! At startup, oxi-dns detects available CPU and memory (cgroup-aware on
//! Linux containers) and computes caps for caches, connection counts, and
//! per-request buffers.  Operators can override any individual cap via the
//! `[limits]` section in `config.toml`; unset fields fall back to the
//! hardware-derived defaults.

use std::sync::OnceLock;
use tracing::info;

use crate::config::LimitsConfig;

const MB: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HardwareProfile {
    pub cpu_cores: usize,
    pub ram_mb: u64,
    /// True if the RAM figure reflects a cgroup limit rather than host memory.
    pub cgroup_limited: bool,
}

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub dns_cache_entries: usize,
    pub ns_cache_entries: usize,
    pub udp_max_inflight: usize,
    pub tcp_max_connections: usize,
    pub dot_max_connections: usize,
    pub doh_max_connections: usize,
    pub doq_max_streams_per_connection: u64,
    pub blocklist_max_bytes: usize,
    pub web_upload_max_bytes: usize,
}

static LIMITS: OnceLock<ResourceLimits> = OnceLock::new();

/// Fetch the initialized limits.  Panics if called before `init`.
pub fn limits() -> &'static ResourceLimits {
    LIMITS
        .get()
        .expect("resources::init() must be called at startup")
}

/// Detect hardware, compute caps, apply config overrides, and install the
/// result as a process-wide singleton.  Safe to call more than once — only
/// the first call wins.
pub fn init(cfg: &LimitsConfig) -> &'static ResourceLimits {
    if let Some(existing) = LIMITS.get() {
        return existing;
    }
    let hw = detect_hardware();
    let limits = compute(&hw, cfg);
    info!(
        "Hardware: {} CPU cores, {} MB RAM{}",
        hw.cpu_cores,
        hw.ram_mb,
        if hw.cgroup_limited {
            " (cgroup-limited)"
        } else {
            ""
        }
    );
    info!(
        "Resource limits: dns_cache={} ns_cache={} udp_inflight={} tcp={} dot={} doh={} doq_streams={} blocklist={}MB upload={}MB",
        limits.dns_cache_entries,
        limits.ns_cache_entries,
        limits.udp_max_inflight,
        limits.tcp_max_connections,
        limits.dot_max_connections,
        limits.doh_max_connections,
        limits.doq_max_streams_per_connection,
        limits.blocklist_max_bytes / MB as usize,
        limits.web_upload_max_bytes / MB as usize,
    );
    let _ = LIMITS.set(limits);
    LIMITS.get().unwrap()
}

pub fn detect_hardware() -> HardwareProfile {
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    let host_ram_bytes = sys.total_memory();

    let (effective_bytes, cgroup_limited) = match detect_cgroup_memory_limit() {
        Some(c) if c < host_ram_bytes => (c, true),
        _ => (host_ram_bytes, false),
    };

    HardwareProfile {
        cpu_cores,
        ram_mb: effective_bytes / MB,
        cgroup_limited,
    }
}

/// Try cgroup v2 (`/sys/fs/cgroup/memory.max`), then cgroup v1
/// (`/sys/fs/cgroup/memory/memory.limit_in_bytes`).  Returns `None` when the
/// file is absent or the limit is "unlimited".
fn detect_cgroup_memory_limit() -> Option<u64> {
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        let trimmed = s.trim();
        if trimmed != "max" {
            if let Ok(v) = trimmed.parse::<u64>() {
                return Some(v);
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
        if let Ok(v) = s.trim().parse::<u64>() {
            // cgroup v1 stores ~i64::MAX when no limit is set.
            if v < (1u64 << 62) {
                return Some(v);
            }
        }
    }
    None
}

/// Compute scaled limits from a hardware profile, then apply per-field overrides.
pub fn compute(hw: &HardwareProfile, cfg: &LimitsConfig) -> ResourceLimits {
    let cpu = hw.cpu_cores.max(1);
    // Treat anything below 64 MB as 64 MB for formula purposes — otherwise
    // sub-floor hardware would compute zero for all caps.
    let ram_mb = hw.ram_mb.max(64) as usize;

    let auto = ResourceLimits {
        dns_cache_entries: (ram_mb * 250).clamp(10_000, 500_000),
        ns_cache_entries: (ram_mb * 50).clamp(2_000, 100_000),
        udp_max_inflight: (cpu * 512).clamp(1_024, 16_384),
        tcp_max_connections: (cpu * 128).clamp(512, 8_192),
        dot_max_connections: (cpu * 128).clamp(512, 8_192),
        doh_max_connections: (cpu * 128).clamp(512, 8_192),
        doq_max_streams_per_connection: (cpu as u64 * 16).clamp(64, 512),
        blocklist_max_bytes: (ram_mb * MB as usize / 8).clamp(50 * MB as usize, 500 * MB as usize),
        web_upload_max_bytes: (ram_mb * MB as usize / 64).clamp(2 * MB as usize, 50 * MB as usize),
    };

    ResourceLimits {
        dns_cache_entries: cfg.dns_cache_entries.unwrap_or(auto.dns_cache_entries),
        ns_cache_entries: cfg.ns_cache_entries.unwrap_or(auto.ns_cache_entries),
        udp_max_inflight: cfg.udp_max_inflight.unwrap_or(auto.udp_max_inflight),
        tcp_max_connections: cfg.tcp_max_connections.unwrap_or(auto.tcp_max_connections),
        dot_max_connections: cfg.dot_max_connections.unwrap_or(auto.dot_max_connections),
        doh_max_connections: cfg.doh_max_connections.unwrap_or(auto.doh_max_connections),
        doq_max_streams_per_connection: cfg
            .doq_max_streams_per_connection
            .unwrap_or(auto.doq_max_streams_per_connection),
        blocklist_max_bytes: cfg
            .blocklist_max_mb
            .map(|mb| mb * MB as usize)
            .unwrap_or(auto.blocklist_max_bytes),
        web_upload_max_bytes: cfg
            .web_upload_max_mb
            .map(|mb| mb * MB as usize)
            .unwrap_or(auto.web_upload_max_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hw(cores: usize, ram_mb: u64) -> HardwareProfile {
        HardwareProfile {
            cpu_cores: cores,
            ram_mb,
            cgroup_limited: false,
        }
    }

    #[test]
    fn pi_class_hardware_gets_reasonable_limits() {
        let limits = compute(&hw(4, 1024), &LimitsConfig::default());
        assert_eq!(limits.dns_cache_entries, 256_000);
        assert_eq!(limits.tcp_max_connections, 512);
        assert_eq!(limits.udp_max_inflight, 2048);
    }

    #[test]
    fn beefy_server_is_ceiling_capped() {
        let limits = compute(&hw(32, 65536), &LimitsConfig::default());
        assert_eq!(limits.dns_cache_entries, 500_000);
        assert_eq!(limits.tcp_max_connections, 4096);
        assert_eq!(limits.doq_max_streams_per_connection, 512);
    }

    #[test]
    fn tiny_hardware_respects_floors() {
        let limits = compute(&hw(1, 32), &LimitsConfig::default());
        assert!(limits.dns_cache_entries >= 10_000);
        assert!(limits.tcp_max_connections >= 512);
        assert!(limits.udp_max_inflight >= 1_024);
    }

    #[test]
    fn config_override_takes_precedence() {
        let cfg = LimitsConfig {
            dns_cache_entries: Some(42),
            web_upload_max_mb: Some(7),
            ..Default::default()
        };
        let limits = compute(&hw(4, 2048), &cfg);
        assert_eq!(limits.dns_cache_entries, 42);
        assert_eq!(limits.web_upload_max_bytes, 7 * 1024 * 1024);
        // Non-overridden fields still auto-scale.
        assert_eq!(limits.tcp_max_connections, 512);
    }
}
