//! The reply half: a `message`-cadence `ReplySink` that sends the terminal
//! document through the same send path `deliver` uses, and keys idempotency
//! on its checkpoint (never the revision number).
use std::sync::Mutex;

use crate::channel::DingTalkChannelAdapter;
use crate::render::MAX_CHUNK_CHARS;
use crate::reply_context::{DingTalkConversationKind, DingTalkReplyContext};
use ironclaw_extension_contracts::external::ExternalConversationRef;
use ironclaw_extension_contracts::reply::{
    ReplyAnswerText, ReplyAudience, ReplyContextBytes, ReplyDisplayText, ReplyDocument,
    ReplyProviderRef, ReplyReconcilePoint, ReplyReconcileRequest, ReplyRevision, ReplySink,
    ReplySinkCheckpoint, ReplySinkOutcome, ReplySinkReport, ReplyTarget,
};
use ironclaw_extension_contracts::tool_adapter::{
    RestrictedEgress, RestrictedEgressError, RestrictedEgressRequest, RestrictedEgressResponse,
};
use ironclaw_host_api::ids::{TenantId, ThreadId, UserId};
use ironclaw_host_api::turn::{TurnActor, TurnRunId, TurnScope};
use serde_json::{Value, json};

type Script =
    Box<dyn Fn(usize) -> Result<RestrictedEgressResponse, RestrictedEgressError> + Send + Sync>;

struct Recorder {
    script: Script,
    requests: Mutex<Vec<RestrictedEgressRequest>>,
}

impl Recorder {
    fn new(script: Script) -> Self {
        Self {
            script,
            requests: Mutex::new(Vec::new()),
        }
    }
    /// Every request is accepted with a distinct `processQueryKey`.
    fn accepting() -> Self {
        Self::new(Box::new(|i| {
            response(200, &json!({"processQueryKey": format!("pqk-{i}")}))
        }))
    }
    fn requests(&self) -> Vec<RestrictedEgressRequest> {
        self.requests.lock().expect("lock").clone()
    }
    fn texts(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|request| {
                let body: Value =
                    serde_json::from_slice(request.body.as_deref().expect("body")).expect("json");
                let param: Value =
                    serde_json::from_str(body["msgParam"].as_str().expect("msgParam"))
                        .expect("msgParam json");
                param["content"].as_str().expect("content").to_string()
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl RestrictedEgress for Recorder {
    async fn send(
        &self,
        request: RestrictedEgressRequest,
    ) -> Result<RestrictedEgressResponse, RestrictedEgressError> {
        let index = {
            let mut requests = self.requests.lock().expect("lock");
            requests.push(request);
            requests.len() - 1
        };
        (self.script)(index)
    }
}

fn response(status: u16, body: &Value) -> Result<RestrictedEgressResponse, RestrictedEgressError> {
    Ok(RestrictedEgressResponse {
        status,
        body: body.to_string().into_bytes(),
        retry_after: None,
    })
}

const CONVERSATION: &str = "cidCONVERSATION";

fn reply_context() -> ReplyContextBytes {
    let bytes = DingTalkReplyContext::new(
        DingTalkConversationKind::Dm,
        CONVERSATION,
        "staff-1",
        Some("dingROBOT".to_string()),
    )
    .encode()
    .expect("encodes");
    ReplyContextBytes::new(bytes).expect("context bytes")
}

enum Terminal {
    Completed,
    Failed(&'static str),
    Cancelled,
}

fn document(answer: &str, terminal: Terminal) -> ReplyDocument {
    let mut document = ReplyDocument::default();
    document.finalize_answer(
        ReplyAnswerText::new(answer).expect("answer text"),
        Vec::new(),
    );
    match terminal {
        Terminal::Completed => document.complete(),
        Terminal::Failed(summary) => {
            document.fail(ReplyDisplayText::new(summary).expect("summary"))
        }
        Terminal::Cancelled => document.cancel(),
    };
    document
}

fn request(
    document: ReplyDocument,
    point: ReplyReconcilePoint,
    checkpoint: Option<ReplySinkCheckpoint>,
    with_context: bool,
) -> ReplyReconcileRequest {
    let user = || UserId::new("reply-user").expect("user id");
    ReplyReconcileRequest {
        revision: ReplyRevision {
            revision: 2,
            document,
        },
        point,
        target: ReplyTarget {
            scope: TurnScope::new_with_owner(
                TenantId::new("reply-tenant").expect("tenant id"),
                None,
                None,
                ThreadId::new("reply-thread").expect("thread id"),
                Some(user()),
            ),
            actor: TurnActor::new(user()),
            run_id: TurnRunId::new(),
            conversation: Some(
                ExternalConversationRef::new(None, CONVERSATION, None, None).expect("conversation"),
            ),
            thread_anchor: None,
            audience: ReplyAudience::Private,
        },
        reply_context: with_context.then(reply_context),
        checkpoint,
        extension_generation: 1,
        materialized_attachments: Vec::new(),
    }
}

fn terminal(document: ReplyDocument) -> ReplyReconcileRequest {
    request(document, ReplyReconcilePoint::Terminal, None, true)
}

fn refs(report: &ReplySinkReport) -> Vec<&str> {
    report
        .evidence
        .provider_refs
        .iter()
        .map(ReplyProviderRef::as_str)
        .collect()
}

fn checkpoint_json(checkpoint: &ReplySinkCheckpoint) -> Value {
    serde_json::from_str(checkpoint.payload()).expect("checkpoint payload is JSON")
}

async fn reconcile(request: ReplyReconcileRequest, egress: &Recorder) -> ReplySinkReport {
    DingTalkChannelAdapter::default()
        .reconcile(request, egress)
        .await
        .expect("a vendor outcome is a report, not an error")
}

#[tokio::test]
async fn terminal_completed_sends_one_batch_send_and_checkpoints_the_refs() {
    let egress = Recorder::accepting();
    let report = reconcile(
        terminal(document("final answer", Terminal::Completed)),
        &egress,
    )
    .await;
    assert!(report.outcome.is_applied(), "{:?}", report.outcome);
    assert_eq!(refs(&report), ["pqk-0"]);
    assert!(
        !report.evidence.read_back_verified,
        "no read-back exists; the sink must not claim one"
    );
    let checkpoint = report.checkpoint.expect("checkpoint");
    assert_eq!(
        checkpoint_json(&checkpoint),
        json!({"terminal_applied": true, "message_refs": ["pqk-0"]})
    );
    let [sent] = egress.requests().try_into().expect("exactly one request");
    assert!(sent.url.ends_with("/v1.0/robot/oToMessages/batchSend"));
    assert_eq!(
        sent.credential.as_ref().map(|handle| handle.as_str()),
        Some("dingtalk_access_token")
    );
    assert_eq!(egress.texts(), ["final answer"]);
}

#[tokio::test]
async fn long_answers_are_sent_as_ordered_character_chunks() {
    let egress = Recorder::accepting();
    let answer = "字".repeat(MAX_CHUNK_CHARS + 5);
    let report = reconcile(terminal(document(&answer, Terminal::Completed)), &egress).await;
    assert!(report.outcome.is_applied(), "{:?}", report.outcome);
    assert_eq!(refs(&report), ["pqk-0", "pqk-1"]);
    assert_eq!(egress.texts().concat(), answer);
}

#[tokio::test]
async fn failed_and_cancelled_runs_send_one_short_line() {
    let egress = Recorder::accepting();
    let report = reconcile(
        terminal(document(
            "partial that must not ship",
            Terminal::Failed("It failed."),
        )),
        &egress,
    )
    .await;
    assert!(report.outcome.is_applied());
    assert_eq!(egress.texts(), ["It failed."]);

    let egress = Recorder::accepting();
    let report = reconcile(terminal(document("half", Terminal::Cancelled)), &egress).await;
    assert!(report.outcome.is_applied());
    let texts = egress.texts();
    assert_eq!(texts.len(), 1);
    assert!(!texts[0].contains("half"));
}

#[tokio::test]
async fn an_empty_completed_answer_sends_nothing_and_is_applied() {
    let egress = Recorder::accepting();
    let report = reconcile(terminal(document("  ", Terminal::Completed)), &egress).await;
    assert!(report.outcome.is_applied());
    assert!(egress.requests().is_empty());
    assert_eq!(
        checkpoint_json(&report.checkpoint.expect("checkpoint")),
        json!({"terminal_applied": true, "message_refs": []})
    );
}

#[tokio::test]
async fn a_repeated_terminal_reconcile_with_the_applied_checkpoint_does_not_resend() {
    let first = Recorder::accepting();
    let applied = reconcile(
        terminal(document("final answer", Terminal::Completed)),
        &first,
    )
    .await
    .checkpoint
    .expect("checkpoint");
    let egress = Recorder::accepting();
    let report = reconcile(
        request(
            document("final answer", Terminal::Completed),
            ReplyReconcilePoint::Terminal,
            Some(applied.clone()),
            true,
        ),
        &egress,
    )
    .await;
    assert!(report.outcome.is_applied());
    assert!(
        egress.requests().is_empty(),
        "the checkpoint short-circuits"
    );
    assert_eq!(refs(&report), ["pqk-0"]);
    assert_eq!(report.checkpoint, Some(applied));
}

#[tokio::test]
async fn non_terminal_points_never_reach_the_vendor() {
    let prior = ReplySinkCheckpoint::new(1, r#"{"unused":true}"#).expect("checkpoint");
    for point in [
        ReplyReconcilePoint::Opened,
        ReplyReconcilePoint::Progress,
        ReplyReconcilePoint::ControlCritical,
        ReplyReconcilePoint::Heartbeat,
    ] {
        let egress = Recorder::accepting();
        let report = reconcile(
            request(
                document("progress", Terminal::Completed),
                point,
                Some(prior.clone()),
                true,
            ),
            &egress,
        )
        .await;
        assert!(report.outcome.is_applied(), "{point:?}");
        assert!(egress.requests().is_empty(), "{point:?}");
        assert_eq!(report.checkpoint, Some(prior.clone()));
    }
}

#[tokio::test]
async fn a_rate_limited_first_chunk_is_retryable_with_no_checkpoint() {
    let egress = Recorder::new(Box::new(|_| response(429, &json!({}))));
    let report = reconcile(
        terminal(document("final answer", Terminal::Completed)),
        &egress,
    )
    .await;
    assert!(
        matches!(report.outcome, ReplySinkOutcome::Retryable { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(report.checkpoint, None);
    assert_eq!(egress.requests().len(), 1);
}

#[tokio::test]
async fn a_failure_after_an_accepted_chunk_is_permanent_and_stays_permanent() {
    let egress = Recorder::new(Box::new(|i| {
        if i == 0 {
            response(200, &json!({"processQueryKey": "pqk-first"}))
        } else {
            response(429, &json!({}))
        }
    }));
    let answer = "a".repeat(MAX_CHUNK_CHARS * 2);
    let report = reconcile(terminal(document(&answer, Terminal::Completed)), &egress).await;
    assert!(
        matches!(report.outcome, ReplySinkOutcome::Permanent { .. }),
        "resending would duplicate the accepted chunk: {:?}",
        report.outcome
    );
    assert_eq!(refs(&report), ["pqk-first"]);
    let checkpoint = report.checkpoint.expect("partial checkpoint");
    assert_eq!(
        checkpoint_json(&checkpoint),
        json!({"terminal_applied": false, "message_refs": ["pqk-first"]})
    );

    // A later reconcile carrying the partial checkpoint never re-sends.
    let later = Recorder::accepting();
    let again = reconcile(
        request(
            document(&answer, Terminal::Completed),
            ReplyReconcilePoint::Terminal,
            Some(checkpoint),
            true,
        ),
        &later,
    )
    .await;
    assert!(matches!(again.outcome, ReplySinkOutcome::Permanent { .. }));
    assert!(later.requests().is_empty());
}

#[tokio::test]
async fn a_server_error_on_the_reply_is_unverified_and_not_resent() {
    // DingTalk may have delivered the reply before answering 5xx; resending
    // could post it twice, so the sink reports it unverified.
    let egress = Recorder::new(Box::new(|_| response(503, &json!({}))));
    let report = reconcile(
        terminal(document("final answer", Terminal::Completed)),
        &egress,
    )
    .await;
    assert!(
        matches!(&report.outcome, ReplySinkOutcome::Ambiguous { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(egress.requests().len(), 1);
}

#[tokio::test]
async fn an_ambiguous_send_is_unverified_and_not_resent() {
    let egress = Recorder::new(Box::new(|_| {
        Err(RestrictedEgressError::Transport {
            reason: "connection reset".into(),
        })
    }));
    let report = reconcile(
        terminal(document("final answer", Terminal::Completed)),
        &egress,
    )
    .await;
    assert!(
        matches!(&report.outcome, ReplySinkOutcome::Ambiguous { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(egress.requests().len(), 1);
}

#[tokio::test]
async fn an_unusable_target_or_context_is_permanent_without_sending() {
    let egress = Recorder::accepting();
    let report = reconcile(
        request(
            document("x", Terminal::Completed),
            ReplyReconcilePoint::Terminal,
            None,
            false,
        ),
        &egress,
    )
    .await;
    assert!(matches!(report.outcome, ReplySinkOutcome::Permanent { .. }));
    assert!(egress.requests().is_empty());

    let mut no_conversation = terminal(document("x", Terminal::Completed));
    no_conversation.target.conversation = None;
    let report = reconcile(no_conversation, &egress).await;
    assert!(matches!(report.outcome, ReplySinkOutcome::Permanent { .. }));
    assert!(egress.requests().is_empty());
}

#[tokio::test]
async fn an_unreadable_checkpoint_is_not_evidence_of_application() {
    let egress = Recorder::accepting();
    for checkpoint in [
        ReplySinkCheckpoint::new(99, r#"{"terminal_applied":true,"message_refs":[]}"#)
            .expect("checkpoint"),
        ReplySinkCheckpoint::new(1, "not json").expect("checkpoint"),
    ] {
        let before = egress.requests().len();
        let report = reconcile(
            request(
                document("final answer", Terminal::Completed),
                ReplyReconcilePoint::Terminal,
                Some(checkpoint),
                true,
            ),
            &egress,
        )
        .await;
        assert!(report.outcome.is_applied());
        assert_eq!(egress.requests().len(), before + 1, "rendered again");
    }
}
