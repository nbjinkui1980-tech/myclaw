# dingtalk — enterprise-internal robot channel (Stream mode)
DingTalk support for one organisation per deployment. The operator creates an
enterprise-internal application with a robot in their own DingTalk
organisation, switches the robot to **Stream mode**, and enters its
`ClientID`/`ClientSecret` in the admin configuration. IronClaw then dials out;
no public address is needed. Extension id: `dingtalk`.
- **Surfaces:** channel only (`messages`): frame control (`stream.rs`),
  `ChannelIngress` (`channel.rs`, `payload.rs`) and message `ChannelDelivery`
  through one OpenAPI send path (`send.rs`, `render.rs`). Implemented:
  message-cadence replies (`reply.rs`), group @robot chat, and push to the
  caller's own single chat (`preference_targets.rs`). Push to a group is not
  implemented (it needs a generic-layer rule; plan "后续项" 12). Remaining
  work is tracked in `docs/internal/2026-11-18-dingtalk-channel-plan.md`.
- **Pairing:** `[channel.connection]` `web_generated_code` with no deep link
  and no inbound prefixes: the user generates a code in IronClaw and sends it
  as the whole message in a single chat. The generic pairing service consumes
  it; this package only normalizes the text. Senders outside the robot's
  organisation never reach pairing.
- **Sending:** `oToMessages/batchSend` (single chat) or `groupMessages/send`
  (group), chosen from the stored reply context. The host exchanges the app
  credentials for the access token and injects `x-acs-dingtalk-access-token`;
  the adapter names the token handle only. `robotCode` comes from the
  originating callback (ADR §14.5). `processQueryKey` is the success
  evidence; anything ambiguous is reported `sent_unverified` and not re-sent.
- **Setup:** `[admin_configuration]` holds `dingtalk_client_id` and
  `dingtalk_client_secret`, **both secret**. ClientID is not sensitive by
  itself, but the host injects connect/exchange request bodies only from
  secret handles, so it is stored encrypted and entered once.
- **Runtime:** `first_party`, service `dingtalk.extension/v1`.
- **Deployment model:** one deployment, one DingTalk organisation, one replica
  (ADR §9). A message is admitted only when `chatbotCorpId` and `senderCorpId`
  are both present and equal; otherwise it is an authenticated no-op with a
  fixed reason code in the logs (see `payload.rs`).
- **Unverified facts** (ADR §8 and §14, checked in Task 20): the gateway host
  `wss-open-connection.dingtalk.com`, the meaning of the two corp ids, whether
  `robotCode` equals `clientId`, rate and length limits.
- **Depends on:** `host_api` and `extension_contracts` only; linked only by the
  binary and tests.
- **Tests:** `cargo test -p ironclaw_dingtalk_extension`. Frames come from the
  constructed fixtures in `tests/fixtures/extensions/dingtalk-stream/` (built
  from the official SDK source, not real captures).
