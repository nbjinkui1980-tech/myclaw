# ironclaw_network

The network policy boundary and hardened outbound transport: target/method
policy evaluation, DNS resolution with private-address denial, redirect and
response-size hardening, and the pinned `reqwest` transport. It is the
workspace's sole egress-policy owner, its only sanctioned `reqwest`/TLS home,
and its only sanctioned WebSocket client (`tokio-tungstenite`, on the same
rustls + native-roots trust) — a module elsewhere would put that cone in the build graph of every
crate that needed even the policy types.

- **Family / layer:** `substrates` / `substrates` · **Package:**
  `ironclaw_network` · **Manifest:**
  `crates/substrates/ironclaw_network/Cargo.toml`
- **Use this when:** an outbound HTTP call or WebSocket must exist — it gets policy-checked,
  resolved with private-IP denial, and sent through the hardened transport.
- **Don't use this when:** you need credentials attached → injection is the
  kernel's obligation handling (`ironclaw_host_runtime`), never done here;
  you're inside a lane → lanes receive a policy-scoped egress handle by
  injection and hold no transport of their own; you're writing a vendor
  allowlist → that is manifest data, not code.

## Public surface

- Policy: `StaticNetworkPolicyEnforcer` (`policy`), URL targeting and
  private-IP checks (`url_target`).
- Egress: `NetworkHttpEgress` port + `PolicyNetworkHttpEgress`,
  `NetworkHttpTransport` (`egress`).
- Resolution: `NetworkResolver` (`resolver`) — denies private and reserved
  addresses before a connection opens.
- Transport: `ReqwestNetworkTransport` (`transport`).
- WebSocket: `WebSocketConnector` port + `PolicyWebSocketConnector`,
  `WebSocketTransport` + `TungsteniteWebSocketTransport`, `WebSocketConnection`
  (split into `WebSocketSender` / `WebSocketReceiver`), `WebSocketLimits`,
  `WebSocketError` (`websocket`). `wss` only, exact allow-listed Wss hosts,
  private-address denial at resolve and dial time, no redirects, bounded
  frames/idle/rate, no URL or query in any error. The upgrade handshake is
  hand-written (`websocket/upgrade.rs`) so the connection ticket lives only in
  `Zeroizing` buffers: policy and DNS see the endpoint without the query, and the
  only copies not scrubbed are rustls's internal plaintext write buffer and the
  kernel's socket buffers. Contract:
  `docs/internal/reborn/contracts/network.md` §4.1.
- Types: `NetworkRequest`, `NetworkHttpRequest`/`NetworkHttpResponse`,
  `NetworkUsage`, `DEFAULT_RESPONSE_BODY_LIMIT` (`types`); `NetworkHttpError`
  (`error`).
- Test seam: `LoopbackWebSocketTransport` — dials one
  loopback address over plaintext `ws` for fake-gateway tests; compiled only
  under `debug_assertions` or `test-support`, constructor-only (no env switch).
- Test seam: `RewriteNetworkTransport` (`test_rewrite`) — env-gated,
  loopback-only host rewriting for E2E harnesses, compiled only under
  `debug_assertions` or the `test-support` feature; a release build refuses to
  activate it.

## Depends on / consumed by

- **Depends on (workspace):** `ironclaw_host_api` only. External: `reqwest`
  (sole owner), `tokio-tungstenite` (sole owner; frame layer), `rustls`/`tokio-rustls`/`rustls-native-certs`/`rustls-pki-types` (WebSocket TLS, same `ring` provider and native roots as `reqwest`), `httparse` and `subtle` (upgrade-response checks), `futures-util`, `url`, `percent-encoding`, `zeroize`, `tokio`, `thiserror`,
  `tracing`.
- **Consumed by (measured 2026-08-05):** 5 normal — `ironclaw_host_runtime`
  (the production caller), `ironclaw_composition` (constructs),
  `ironclaw_extension_host`, `ironclaw_extension_manager`, and
  `ironclaw_sandbox` (the lane's egress-interception machinery; a measured
  deviation from the lanes family target — see
  [`crates/lanes/AGENTS.md`](../../lanes/AGENTS.md)).

## Invariants

- **Fail closed:** no matching target pattern, or no allowed targets configured,
  means deny.
- **Host matching stays simple:** exact host or one leading wildcard label
  (`*.example.com`), never regex.
- **Scope travels intact:** tenant/user/agent/project scope is preserved in
  requests, permits, and errors.
- **Mechanism only:** no secret injection, resource reservation, audit/event
  emission, authorization/approval decisions, or product workflow here — those
  belong to the kernel and the owning domains.
- **No upward edges:** the `ironclaw_network` `BoundaryRule` in
  `reborn_dependency_boundaries.rs` (`reborn_crate_dependency_boundaries_hold`)
  forbids runtime/workflow/secret/filesystem/resource/event/approval/
  authorization crates by name.
- **One WebSocket client:** `reborn_websocket_single_network_boundary` fails
  any other crate that depends on, or names in production `src/`, a WebSocket
  client library, and pins WebSocket TLS to `reqwest`'s native-roots trust.
- **Runtime crates cannot bypass it:**
  `reborn_runtime_http_egress_has_single_network_boundary` scans the lane and
  kernel `src/` trees for `reqwest::Client`, ad-hoc DNS, and revived SSRF
  helpers.

## Tests

```bash
cargo test -p ironclaw_network
cargo test -p ironclaw_architecture_tests   # boundary + single-egress gates
```

## See also

Family boundary: [`crates/substrates/AGENTS.md`](../AGENTS.md). Contracts:
`docs/internal/reborn/contracts/network.md`, `docs/internal/reborn/contracts/kernel-boundary.md`,
`docs/internal/reborn/contracts/resources.md`. (The crate's working rules were folded
into the Invariants above on 2026-08-06; this README is the crate-local home.)
