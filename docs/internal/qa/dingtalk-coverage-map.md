# DingTalk channel coverage map

Inventory of the DingTalk channel's behaviors (enterprise-internal robot,
Stream mode; plan `docs/internal/2026-11-18-dingtalk-channel-plan.md`) against
the automated tests that pin them. Every test name below exists in the tree;
`cargo test <name>` locates each. Hardening (Task 19) adds rows as it lands. Real-DingTalk
acceptance (Task 20) is manual and is not listed here.

Statuses: **covered** (a named test pins the behavior), **partial** (the note
names the uncovered leg), **not-automated** (reason given).

Suites:

- `cargo test -p ironclaw_dingtalk_extension` — adapter tier: in-module `#[cfg(test)]` suites
  (`inbound`, `delivery`, `reply`, `manifest`, `channel_conformance`,
  `preference_targets`, under `src/tests/`).
- `cargo test -p ironclaw_integration_tests --test reborn_integration_extension_dingtalk_pairing`
  — composed runtime: the shipped manifest, the stream supervisor over a
  loopback gateway, host-side token exchange, the production channel host
  assembly. Assertions are made at the gateway (ACK frames) and network-egress
  (path, body, injected token header) seams.
- `cargo test -p ironclaw --bin ironclaw native_extensions` — binary wiring.
- `cargo test -p ironclaw_architecture_tests` — dependency boundaries.

| Behavior | Status | Evidence |
|---|---|---|
| Manifest declares one exact gateway host, stream connect and subscription | **covered** | `channel_validates_and_declares_a_stream_ingress_on_one_exact_host`, `no_wildcard_hosts_and_no_session_webhook_paths` |
| Credentials are secret, required admin fields | **covered** | `admin_credentials_are_secret_required_fields` |
| Sends name the exchanged token handle and declared paths only | **covered** | `sends_use_a_host_exchanged_token_and_declared_send_paths`, `dm_notice_posts_batch_send_with_the_callback_robot_code_and_token_handle` |
| Frame control: CALLBACK hands on `data` and ACKs; `disconnect` reconnects; other SYSTEM frames ACK only | **covered** | `callback_frame_delivers_its_data_and_acks_with_the_frame_message_id`, `disconnect_acks_then_reconnects`, `other_system_frames_are_acked_only`, `unknown_topics_and_types_are_dropped_with_an_ack`, `malformed_frames_are_parse_errors_not_panics`, `dingtalk_frame_control_satisfies_the_stream_conformance_contract` |
| Single-chat text normalizes to a direct message (actor `senderStaffId`, event id `msgId`) | **covered** | `single_chat_text_normalizes_to_a_direct_message`, `dm_text_is_trimmed_and_empty_text_is_ignored`, `session_key_is_the_bounded_conversation_id` |
| Organisation rule: mismatched or missing corp ids never reach admission | **covered** | `corp_id_rule_is_stateless_and_fails_closed`, `sender_without_a_staff_id_is_ignored` |
| Malformed or overlong callbacks fail without panics | **covered** | `malformed_callback_data_is_a_parse_error`, `overlong_text_is_rejected_at_the_bound` |
| Non-text messages are ignored | **covered** | `non_text_messages_are_ignored` |
| Group @robot: BotMention trigger, group reply context, one actor per member | **covered** | `an_at_mention_in_a_group_is_a_bot_mention_routed_to_the_group`, `two_members_of_one_group_are_two_actors_in_one_conversation` |
| Group message without @robot is an authenticated no-op with a fixed reason | **covered** | `a_group_message_without_an_at_of_the_robot_is_ignored`, `an_unaddressed_group_message_logs_a_fixed_reason_only` |
| A leading `@` token is never removed from the text (whether DingTalk writes the robot mention into `text.content` is unverified, Task 20) | **covered** | `a_leading_at_token_is_never_removed_from_the_text` |
| External or unidentified group members are never admitted; malformed group fields | **covered** | `external_or_unidentified_group_members_are_never_admitted`, `malformed_group_fields_are_ignored_or_parse_errors_never_panics` |
| Group replies post to `groupMessages/send`; an ephemeral notice goes to the member's single chat | **covered** | `group_context_posts_group_messages_send`, `an_ephemeral_group_notice_goes_to_that_member_alone_as_a_single_chat`, `an_ephemeral_notice_for_a_foreign_actor_kind_is_refused_without_sending` |
| Group journey: two paired members each run as themselves and are answered on `groupMessages/send`; chatter admits no turn; an unpaired member's nudge goes to their single chat, throttled per conversation | **covered** | `dingtalk_group_mentions_run_as_each_paired_member_and_reply_to_the_group` |
| Rendering splits on character boundaries | **covered** | `chunks_split_on_character_boundaries`, `long_text_is_sent_as_ordered_chunks`, `long_answers_are_sent_as_ordered_character_chunks` |
| Send errors: 429 retryable, 5xx `sent_unverified` (never re-sent), other 4xx permanent, 401 unauthorized, per-recipient lists honored | **covered** | `vendor_errors_are_classified`, `per_recipient_lists_override_a_2xx`, `a_server_error_after_an_accepted_chunk_is_unverified_and_stops_the_rest` |
| Ambiguous sends are `sent_unverified` and never re-sent | **covered** | `ambiguous_outcomes_are_marked_unverified_and_never_resent`, `an_ambiguous_send_is_unverified_and_not_resent`, `a_server_error_on_the_reply_is_unverified_and_not_resent` |
| Missing or foreign reply context fails closed before any request | **covered** | `a_missing_robot_code_or_context_fails_closed_without_sending`, `a_context_for_another_conversation_is_refused`, `an_unusable_target_or_context_is_permanent_without_sending` |
| Error reasons never echo vendor bodies or ids | **covered** | `reasons_never_echo_vendor_bodies` |
| Reply sink: one terminal send, checkpointed `processQueryKey` refs, idempotent repeat | **covered** | `terminal_completed_sends_one_batch_send_and_checkpoints_the_refs`, `a_repeated_terminal_reconcile_with_the_applied_checkpoint_does_not_resend`, `non_terminal_points_never_reach_the_vendor`, `an_unreadable_checkpoint_is_not_evidence_of_application` |
| Reply sink: partial render stays permanent; failure and cancel send one line | **covered** | `a_failure_after_an_accepted_chunk_is_permanent_and_stays_permanent`, `a_rate_limited_first_chunk_is_retryable_with_no_checkpoint`, `failed_and_cancelled_runs_send_one_short_line`, `an_empty_completed_answer_sends_nothing_and_is_applied` |
| Shared channel conformance (ingress, delivery, message-cadence reply) | **covered** | `dingtalk_adapter_satisfies_the_channel_conformance_contract` |
| Pairing: web-generated code, no deep link, no prefixes | **covered** | `pairing_is_a_web_generated_code_without_deep_link_or_prefixes`, `a_bare_pairing_code_in_a_single_chat_reaches_the_host_as_direct_chat_text` |
| Unpaired DM gets the connect notice through the token exchange; code pairs; outsider cannot pair | **covered** | `dingtalk_code_pairing_binds_the_sender_and_notices_leave_through_the_token_exchange` |
| Single-chat journey: paired frame runs a turn and the reply leaves once via `batchSend` with the exchanged token; Delivered attempt recorded | **covered** | `dingtalk_single_chat_journey_replies_through_the_reply_sink` |
| Push targets: `dm:<staffId>:<conversationId>` and `group:<conversationId>` round-trip; malformed refs decode to nothing; unsafe inputs are not encoded | **covered** | `a_personal_dm_round_trips_with_its_staff_id_and_conversation`, `a_group_round_trips_without_a_dm_actor`, `malformed_refs_decode_to_nothing`, `encoding_refuses_unsafe_or_mismatched_inputs` |
| Push to the caller's own DM names that staff id and the context's robot code; missing or foreign context fails closed | **covered** | `a_push_to_the_callers_own_dm_names_that_staff_id_and_the_context_robot_code`, `a_push_without_a_reply_context_or_robot_code_fails_closed`, `a_push_with_another_conversations_context_is_refused` |
| `builtin.outbound_deliver` reaches only the caller's own single chat; another DM and a group send nothing | **covered** | `dingtalk_push_reaches_only_the_callers_own_single_chat` |
| Group push | **not-automated** | Not offered: the generic provider has no shared-conversation targets (plan follow-up 12) |
| Binary binds ingress, frame control, reply and delivery | **covered** | `dingtalk_factory_and_binding_bind_every_channel_half` (also pins the push codec and no package provider) |
| Only the binary links the package; package depends on contracts only | **covered** | `dingtalk_boundary_rule_is_armed`, `reborn_cli_binary_crate_stays_separate_from_v1_root` |
| Gateway host, ACK and send field shapes against real DingTalk | **not-automated** | Fixtures are built from the official SDK source, not captured traffic; verified manually in Task 20 |

Unrelated finding for a separate issue: `telegram-coverage-map.md` cites
`cargo test --test reborn_integration_telegram_journey`, a test target that
does not exist in the tree.
