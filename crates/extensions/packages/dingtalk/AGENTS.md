# Agent Map — ironclaw_dingtalk_extension (`crates/extensions/packages/dingtalk/`)
## Start Here
- Read `README.md` for orientation; this map plus `Cargo.toml` and the source
  carry the working rules. The plan is
  `docs/internal/2026-11-18-dingtalk-channel-plan.md`, the decisions are in
  `docs/internal/2026-11-18-dingtalk-stream-adr.md` (§8 lists which DingTalk
  facts are still unverified; §14 records the package decisions).
- This directory is the whole DingTalk **package**: the crate and its
  `manifest.toml` live together, per PROPOSAL §5's package rule.
- Read `src/lib.rs` first, then:
  - `stream.rs` — frame control: pure `decode`/`session_key` over one frame.
  - `payload.rs` — callback parsing and the stateless organisation rule.
  - `channel.rs` — the `ChannelIngress` and `ChannelDelivery` implementations.
  - `send.rs` / `render.rs` — the one send path (request shapes verified
    against the official Go SDK, ADR §14.4) and character-boundary chunking.
  - `reply_context.rs` — the opaque context stamped on each message for replies.
  - Re-derive the list with `ls crates/extensions/packages/dingtalk/src/`.
- Read the contract before changing channel behavior:
  `crates/contracts/ironclaw_extension_contracts/` — `ChannelIngress`,
  `ChannelStreamControl`, `StreamFrameDecision` (`channel_adapter.rs`).
## What This Crate Owns
- DingTalk's frame protocol and bot-callback mapping onto the shared channel
  DTOs. No I/O and no secrets: the host owns the WebSocket, the connect call,
  token exchange and every credential.
- The organisation rule: admit only when `chatbotCorpId` and `senderCorpId` are
  present, non-empty and equal. It is stateless on purpose (no pin); do not
  add process-local memory of "the first organisation seen".
## Do Not Move In Here
- Shared channel contracts, registry semantics, host auth/evidence minting,
  network egress, secret storage, pairing services.
- Any use of DingTalk's `sessionWebhook` (it carries a query string, which the
  egress path rules forbid).
## Dependency Rule
`ironclaw_*` dependencies are `host_api` and `extension_contracts` only. No
assistant, registry, extension host or network crate. Pinned by the
`ironclaw_dingtalk_extension` BoundaryRule and `dingtalk_boundary_rule_is_armed`
in `crates/app/ironclaw_architecture_tests/tests/reborn_dependency_boundaries.rs`.
## Validation
- `cargo test -p ironclaw_dingtalk_extension`
- `cargo test -p ironclaw_architecture_tests` after dependency or API changes
## Agent Notes
- Never log ids, corp ids, nicknames or message text; log fixed reason codes.
- Treat all callback text as untrusted user input.
- Add tests before widening supported payload forms.
