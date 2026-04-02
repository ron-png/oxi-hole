use crate::config::Config;
use std::path::Path;
use std::process::Command;

const VALID_KEYS: &[&str] = &[
    "dns.listen",
    "dns.dot_listen",
    "dns.doh_listen",
    "dns.doq_listen",
    "web.listen",
];

#[derive(Debug, PartialEq)]
pub enum ResolvedAction {
    None,
    Disable,
    Enable,
}

pub fn run(config_path: &Path, args: &[String]) -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("--reconfigure requires root privileges. Run with sudo.");
    }

    let changes = parse_changes(args)?;
    let mut config = Config::load(config_path)?;

    let old_dns_listen = config.dns.listen.clone();
    let new_dns_listen = collect_values(&changes, "dns.listen");

    apply_changes(&mut config, &changes);

    if !new_dns_listen.is_empty() {
        let action = needs_resolved_change(&old_dns_listen, &new_dns_listen);
        match action {
            ResolvedAction::Disable => {
                println!("Disabling systemd-resolved stub listener...");
                disable_resolved_stub();
            }
            ResolvedAction::Enable => {
                println!("Re-enabling systemd-resolved stub listener...");
                enable_resolved_stub();
            }
            ResolvedAction::None => {}
        }
    }

    config.save(config_path)?;
    println!("Configuration saved to {}", config_path.display());

    restart_service();
    println!("Reconfiguration complete.");
    Ok(())
}

pub fn parse_changes(args: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut changes = Vec::new();
    for arg in args {
        let (key, value) = arg
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("expected key=value format, got '{}'", arg))?;
        if !VALID_KEYS.contains(&key) {
            anyhow::bail!(
                "unknown config key '{}'. Valid keys: {}",
                key,
                VALID_KEYS.join(", ")
            );
        }
        changes.push((key.to_string(), value.to_string()));
    }
    if changes.is_empty() {
        anyhow::bail!("--reconfigure requires at least one key=value argument");
    }
    Ok(changes)
}

pub fn apply_changes(config: &mut Config, changes: &[(String, String)]) {
    let dns_listen = collect_values(changes, "dns.listen");
    if !dns_listen.is_empty() {
        config.dns.listen = dns_listen;
    }

    let web_listen = collect_values(changes, "web.listen");
    if !web_listen.is_empty() {
        config.web.listen = web_listen;
    }

    if has_key(changes, "dns.dot_listen") {
        config.dns.dot_listen = collect_optional_values(changes, "dns.dot_listen");
    }

    if has_key(changes, "dns.doh_listen") {
        config.dns.doh_listen = collect_optional_values(changes, "dns.doh_listen");
    }

    if has_key(changes, "dns.doq_listen") {
        config.dns.doq_listen = collect_optional_values(changes, "dns.doq_listen");
    }
}

fn has_key(changes: &[(String, String)], key: &str) -> bool {
    changes.iter().any(|(change_key, _)| change_key == key)
}

fn collect_values(changes: &[(String, String)], key: &str) -> Vec<String> {
    changes
        .iter()
        .filter(|(change_key, _)| change_key == key)
        .map(|(_, value)| value.clone())
        .collect()
}

fn collect_optional_values(changes: &[(String, String)], key: &str) -> Option<Vec<String>> {
    let values: Vec<String> = collect_values(changes, key)
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect();

    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

pub fn needs_resolved_change(old_listen: &[String], new_listen: &[String]) -> ResolvedAction {
    let old_is_53 = old_listen.iter().any(|addr| is_port53_local(addr));
    let new_is_53 = new_listen.iter().any(|addr| is_port53_local(addr));

    match (old_is_53, new_is_53) {
        (false, true) => ResolvedAction::Disable,
        (true, false) => ResolvedAction::Enable,
        _ => ResolvedAction::None,
    }
}

fn is_port53_local(addr: &str) -> bool {
    let port = addr.rsplit(':').next().unwrap_or("");
    if port != "53" {
        return false;
    }
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
    matches!(host, "0.0.0.0" | "127.0.0.1" | "" | "[::]" | "[::1]")
}

fn has_systemd_resolved() -> bool {
    Path::new("/run/systemd/system").exists()
        && Command::new("systemctl")
            .args(["list-unit-files", "systemd-resolved.service"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

fn disable_resolved_stub() {
    if !has_systemd_resolved() {
        return;
    }
    let _ = std::fs::create_dir_all("/etc/systemd/resolved.conf.d");
    let _ = std::fs::write(
        "/etc/systemd/resolved.conf.d/oxi-dns.conf",
        "# Created by oxi-dns --reconfigure\n[Resolve]\nDNSStubListener=no\n",
    );

    let search_line = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("search "))
        .map(|l| l.to_string());

    let mut content = String::from("# Generated by oxi-dns --reconfigure\nnameserver 127.0.0.1\n");
    if let Some(search) = search_line {
        content = format!(
            "# Generated by oxi-dns --reconfigure\n{}\nnameserver 127.0.0.1\n",
            search
        );
    }
    let _ = std::fs::remove_file("/etc/resolv.conf");
    let _ = std::fs::write("/etc/resolv.conf", content);
    let _ = Command::new("systemctl")
        .args(["restart", "systemd-resolved"])
        .output();
    println!("systemd-resolved stub listener disabled");
}

fn enable_resolved_stub() {
    if !has_systemd_resolved() {
        return;
    }
    let _ = std::fs::remove_file("/etc/systemd/resolved.conf.d/oxi-dns.conf");
    let _ = std::fs::remove_dir("/etc/systemd/resolved.conf.d");
    let _ = std::fs::remove_file("/etc/resolv.conf");
    if Path::new("/run/systemd/resolve/stub-resolv.conf").exists() {
        let _ =
            std::os::unix::fs::symlink("/run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf");
    } else if Path::new("/run/systemd/resolve/resolv.conf").exists() {
        let _ = std::os::unix::fs::symlink("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf");
    }
    let _ = Command::new("systemctl")
        .args(["enable", "systemd-resolved"])
        .output();
    let _ = Command::new("systemctl")
        .args(["restart", "systemd-resolved"])
        .output();
    println!("systemd-resolved stub listener re-enabled");
}

fn restart_service() {
    if Path::new("/run/systemd/system").exists() {
        println!("Restarting oxi-dns service...");
        let _ = Command::new("systemctl")
            .args(["restart", "oxi-dns"])
            .output();
    } else if cfg!(target_os = "macos") {
        println!("Restarting oxi-dns service...");
        let _ = Command::new("launchctl")
            .args(["unload", "/Library/LaunchDaemons/com.oxi-dns.server.plist"])
            .output();
        let _ = Command::new("launchctl")
            .args(["load", "/Library/LaunchDaemons/com.oxi-dns.server.plist"])
            .output();
    } else if Path::new("/etc/init.d/oxi-dns").exists() {
        println!("Restarting oxi-dns service...");
        let _ = Command::new("rc-service")
            .args(["oxi-dns", "restart"])
            .output();
    } else {
        println!("Could not detect init system. Please restart oxi-dns manually.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_change() {
        let changes = parse_changes(&["dns.listen=0.0.0.0:5353".to_string()]).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0],
            ("dns.listen".to_string(), "0.0.0.0:5353".to_string())
        );
    }

    #[test]
    fn parse_multiple_changes() {
        let changes = parse_changes(&[
            "dns.listen=0.0.0.0:5353".to_string(),
            "web.listen=0.0.0.0:3000".to_string(),
        ])
        .unwrap();
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn parse_all_supported_listen_keys() {
        let changes = parse_changes(&[
            "dns.listen=0.0.0.0:5353".to_string(),
            "web.listen=0.0.0.0:3000".to_string(),
            "dns.dot_listen=0.0.0.0:8853".to_string(),
            "dns.doh_listen=0.0.0.0:8443".to_string(),
            "dns.doq_listen=0.0.0.0:8853".to_string(),
        ])
        .unwrap();

        assert_eq!(changes.len(), 5);
        assert!(changes.contains(&("dns.listen".to_string(), "0.0.0.0:5353".to_string())));
        assert!(changes.contains(&("web.listen".to_string(), "0.0.0.0:3000".to_string())));
        assert!(changes.contains(&("dns.dot_listen".to_string(), "0.0.0.0:8853".to_string())));
        assert!(changes.contains(&("dns.doh_listen".to_string(), "0.0.0.0:8443".to_string())));
        assert!(changes.contains(&("dns.doq_listen".to_string(), "0.0.0.0:8853".to_string())));
    }

    #[test]
    fn parse_repeated_listen_keys() {
        let changes = parse_changes(&[
            "dns.listen=0.0.0.0:53".to_string(),
            "dns.listen=[::]:53".to_string(),
            "dns.dot_listen=0.0.0.0:853".to_string(),
            "dns.dot_listen=[::]:853".to_string(),
        ])
        .unwrap();

        assert_eq!(changes.len(), 4);
        assert_eq!(
            collect_values(&changes, "dns.listen"),
            vec!["0.0.0.0:53".to_string(), "[::]:53".to_string()]
        );
        assert_eq!(
            collect_optional_values(&changes, "dns.dot_listen"),
            Some(vec!["0.0.0.0:853".to_string(), "[::]:853".to_string()])
        );
    }

    #[test]
    fn parse_invalid_format() {
        let result = parse_changes(&["badformat".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_key() {
        let result = parse_changes(&["unknown.key=value".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_args() {
        let result = parse_changes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn apply_dns_listen() {
        let mut config = Config::default();
        let changes = vec![("dns.listen".to_string(), "0.0.0.0:5353".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.listen, vec!["0.0.0.0:5353".to_string()]);
    }

    #[test]
    fn apply_multiple_dns_listeners() {
        let mut config = Config::default();
        let changes = vec![
            ("dns.listen".to_string(), "0.0.0.0:53".to_string()),
            ("dns.listen".to_string(), "[::]:53".to_string()),
            ("web.listen".to_string(), "0.0.0.0:9853".to_string()),
            ("web.listen".to_string(), "[::]:9853".to_string()),
        ];
        apply_changes(&mut config, &changes);
        assert_eq!(
            config.dns.listen,
            vec!["0.0.0.0:53".to_string(), "[::]:53".to_string()]
        );
        assert_eq!(
            config.web.listen,
            vec!["0.0.0.0:9853".to_string(), "[::]:9853".to_string()]
        );
    }

    #[test]
    fn apply_web_listen() {
        let mut config = Config::default();
        let changes = vec![("web.listen".to_string(), "0.0.0.0:3000".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.web.listen, vec!["0.0.0.0:3000".to_string()]);
    }

    #[test]
    fn apply_dot_listen() {
        let mut config = Config::default();
        let changes = vec![("dns.dot_listen".to_string(), "0.0.0.0:853".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.dot_listen, Some(vec!["0.0.0.0:853".to_string()]));
    }

    #[test]
    fn apply_doh_and_doq_listen() {
        let mut config = Config::default();
        let changes = vec![
            ("dns.doh_listen".to_string(), "0.0.0.0:443".to_string()),
            ("dns.doq_listen".to_string(), "0.0.0.0:853".to_string()),
        ];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.doh_listen, Some(vec!["0.0.0.0:443".to_string()]));
        assert_eq!(config.dns.doq_listen, Some(vec!["0.0.0.0:853".to_string()]));
    }

    #[test]
    fn apply_multiple_optional_listeners() {
        let mut config = Config::default();
        let changes = vec![
            ("dns.dot_listen".to_string(), "0.0.0.0:853".to_string()),
            ("dns.dot_listen".to_string(), "[::]:853".to_string()),
            ("dns.doh_listen".to_string(), "0.0.0.0:443".to_string()),
            ("dns.doh_listen".to_string(), "[::]:443".to_string()),
        ];
        apply_changes(&mut config, &changes);
        assert_eq!(
            config.dns.dot_listen,
            Some(vec!["0.0.0.0:853".to_string(), "[::]:853".to_string()])
        );
        assert_eq!(
            config.dns.doh_listen,
            Some(vec!["0.0.0.0:443".to_string(), "[::]:443".to_string()])
        );
    }

    #[test]
    fn apply_clear_optional_listen() {
        let mut config = Config::default();
        config.dns.dot_listen = Some(vec!["0.0.0.0:853".to_string()]);
        let changes = vec![("dns.dot_listen".to_string(), "".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.dot_listen, None);
    }

    #[test]
    fn resolved_disable_for_port53() {
        assert_eq!(
            needs_resolved_change(&["0.0.0.0:5353".to_string()], &["0.0.0.0:53".to_string()]),
            ResolvedAction::Disable
        );
    }

    #[test]
    fn resolved_enable_leaving_port53() {
        assert_eq!(
            needs_resolved_change(&["0.0.0.0:53".to_string()], &["0.0.0.0:5353".to_string()]),
            ResolvedAction::Enable
        );
    }

    #[test]
    fn resolved_none_for_non53() {
        assert_eq!(
            needs_resolved_change(&["0.0.0.0:5353".to_string()], &["0.0.0.0:8053".to_string()]),
            ResolvedAction::None
        );
    }

    #[test]
    fn resolved_none_same_port53() {
        assert_eq!(
            needs_resolved_change(&["0.0.0.0:53".to_string()], &["127.0.0.1:53".to_string()]),
            ResolvedAction::None
        );
    }

    #[test]
    fn resolved_change_checks_all_dns_listeners() {
        assert_eq!(
            needs_resolved_change(
                &["0.0.0.0:5353".to_string(), "[::]:5353".to_string()],
                &["0.0.0.0:5353".to_string(), "[::]:53".to_string()]
            ),
            ResolvedAction::Disable
        );
        assert_eq!(
            needs_resolved_change(
                &["0.0.0.0:53".to_string(), "[::]:53".to_string()],
                &["0.0.0.0:5353".to_string(), "[::]:5353".to_string()]
            ),
            ResolvedAction::Enable
        );
    }

    #[test]
    fn is_port53_various() {
        assert!(is_port53_local("0.0.0.0:53"));
        assert!(is_port53_local("127.0.0.1:53"));
        assert!(!is_port53_local("192.168.1.10:53"));
        assert!(!is_port53_local("0.0.0.0:5353"));
    }
}
