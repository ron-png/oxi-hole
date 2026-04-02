# Cache Flush on Settings Change

## Problem

When a filtering setting is toggled (safe search, block ads, youtube restricted, etc.), the DNS cache retains stale entries. Cached responses from before the change bypass the new filtering rules until they expire naturally (up to 24 hours).

## Solution

Flush the entire DNS cache whenever any filtering-related setting is changed, by calling `upstream.flush_cache()` at the API layer immediately after the setting mutation.

## Approach

**Full cache flush at the API call site (Approach A).** The flush is explicit in each endpoint handler rather than embedded in the feature/blocklist managers. This keeps the cache dependency at the web layer and avoids coupling lower-level modules to the cache.

## Endpoints to Modify

All in `src/web/mod.rs`. Each gets one additional line: `state.upstream.flush_cache();`

| Endpoint | Handler | What it changes |
|----------|---------|----------------|
| `POST /api/features/{id}` | `api_toggle_feature` | Toggles safe search, ads, youtube restricted, nsfw, root servers |
| `POST /api/blocking/enabled` | (blocking enabled toggle) | Enables/disables all blocking |
| `POST /api/blocking/mode` | (blocking mode setter) | Changes blocked response format |
| `POST /api/blocking/custom` | (custom blocked domains) | Adds/removes custom blocked domains |
| `POST /api/blocking/allowlist` | (allowlist setter) | Adds/removes allowlisted domains |
| `POST /api/settings/ipv6` | (IPv6 toggle) | Toggles AAAA query handling |

## What `flush_cache()` Does

Already implemented in `src/dns/upstream.rs`. Clears the `DashMap` cache and resets hit/miss counters. No new flush logic needed.

## Trade-offs

- **Simplicity over precision:** A full flush is coarser than selective invalidation but far simpler. The cache repopulates naturally within seconds as new queries arrive.
- **Explicit over automatic:** Adding the flush call to each endpoint means a future endpoint could forget it, but keeps the architecture clean with no new cross-module dependencies.

## Out of Scope

- Selective cache invalidation (removing only affected domains)
- Cache warming after flush
