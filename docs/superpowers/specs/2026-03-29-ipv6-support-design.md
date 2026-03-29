# IPv6 Support

## Problem

oxi-hole has partial IPv6 support — listeners and AAAA query handling work, but upstream queries to IPv6 DNS servers fail (hardcoded IPv4 source binding), root server fallback is IPv4-only, default config only binds IPv4, and there's no way to filter AAAA records from responses for IPv4-only networks.

## Solution

Fix the upstream bugs, add dual-stack listen addresses by default, and add a web UI toggle to filter AAAA records from DNS responses.

---

## 1. Upstream Source Binding Fix

`forward_udp()` and the DoQ endpoint in `src/dns/upstream.rs` hardcode `"0.0.0.0:0"` as the source bind address. This fails when the target upstream is IPv6.

**Fix:** Detect the address family of the target and bind accordingly:

```rust
let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
```

**Applies to:**
- `forward_udp()` — plain UDP upstream queries
- DoQ `quinn::Endpoint` creation — QUIC upstream queries

DoT and DoH use TCP/HTTP clients that handle address family automatically — no changes needed.

## 2. Root Server Fallback IPv6 Support

The `resolve_via_root_servers` function in `src/dns/upstream.rs` only uses IPv4 root servers and only queries for A records.

**Changes:**
- Add `ROOT_SERVERS_V6` constant with IPv6 addresses of root servers (e.g. `2001:503:ba3e::2:30` for a.root-servers.net)
- Query for both A and AAAA records during the iterative walk, collecting all resolved addresses
- Extract both A and AAAA glue records from referral responses
- Try IPv4 root servers first (more universally reachable), fall back to IPv6 if all IPv4 fail

This ensures `resolve_via_root_servers` returns both IPv4 and IPv6 addresses, and works on IPv6-only networks.

## 3. Dual-Stack Listen Addresses

Change listen address config fields from a single string to a list, binding both IPv4 and IPv6 by default.

### Config format

```toml
[dns]
listen = ["0.0.0.0:53", "[::]:53"]

[web]
listen = ["0.0.0.0:8080", "[::]:8080"]
```

Optional DoT/DoH/DoQ fields follow the same pattern when set:
```toml
dot_listen = ["0.0.0.0:853", "[::]:853"]
doh_listen = ["0.0.0.0:443", "[::]:443"]
doq_listen = ["0.0.0.0:8853", "[::]:8853"]
```

### Backward compatibility

If `listen` is a plain string (old config format), deserialize it as a single-element list. Use `#[serde(deserialize_with = "...")]` or an untagged enum to accept both `"0.0.0.0:53"` and `["0.0.0.0:53", "[::]:53"]`.

### Runtime

Each listener function takes a `&[String]` of addresses and spawns one task per address. The existing `start_*` functions are called in a loop, or internally loop over the address list. All spawned tasks are collected and awaited together.

### Default config

New installs get dual-stack defaults. Existing single-string configs continue to work (IPv4-only until user changes them).

## 4. IPv6 Response Filtering Toggle

A web UI toggle that controls whether AAAA records are included in DNS responses. Useful for IPv4-only networks.

### Config

New field in system config:
```toml
[system]
ipv6_enabled = true   # default
```

### Behavior

- `ipv6_enabled = true` (default): upstream responses passed through unchanged
- `ipv6_enabled = false`:
  - Strip AAAA records from the answer section of upstream responses before returning to client
  - For direct AAAA queries: return NOERROR with empty answer section
  - Blocked domain AAAA responses (`::` / custom IPv6) are also suppressed

### Backend

- `ipv6_enabled` stored in `AppState` as `Arc<AtomicBool>` for lock-free reads on the hot path (every DNS query)
- Filtering applied in the DNS handler after receiving upstream response, before sending to client
- Toggled via existing config save endpoint; takes effect immediately (no restart)

### Frontend

- Toggle switch in the Settings section alongside existing toggles (auto-update, blocking mode)
- Label: "IPv6 (AAAA)" with subtitle "Include IPv6 records in DNS responses"

### What this does NOT affect

- Listen addresses — dual-stack binding is independent of this toggle
- Upstream queries — still sent over IPv6 if the upstream server is IPv6
- The toggle only filters AAAA records in responses to clients

## 5. Files Modified

- **`src/config.rs`** — Change `listen` fields from `String` to `Vec<String>` with backward-compatible deserialization, add `ipv6_enabled: bool` to system config
- **`src/dns/upstream.rs`** — Fix `forward_udp` and DoQ source binding, add `ROOT_SERVERS_V6`, update `resolve_via_root_servers` for AAAA support and IPv6 glue records
- **`src/dns/handler.rs`** — Add AAAA filtering logic when `ipv6_enabled` is false
- **`src/dns/mod.rs`** — Update `DnsServer` to accept and iterate over address lists
- **`src/dns/listener_udp.rs`** — Accept address list, spawn per address
- **`src/dns/listener_dot.rs`** — Accept address list, spawn per address
- **`src/dns/listener_doh.rs`** — Accept address list, spawn per address
- **`src/dns/listener_doq.rs`** — Accept address list, spawn per address
- **`src/web/mod.rs`** — Accept address list for web server binding, add `ipv6_enabled` to `AppState`, expose via config save
- **`src/web/dashboard.html`** — Add IPv6 toggle in Settings section
- **`src/main.rs`** — Thread `ipv6_enabled` into DNS handler, update listener spawning for address lists
