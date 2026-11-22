//! Single outbound-WebSocket boundary.
//!
//! `ironclaw_network` is the one sanctioned WebSocket *client* in the
//! workspace (stream-ingress ADR 1.1/1.3), exactly as it is the one `reqwest`
//! owner. A second client would bypass the host allow-list, private-address
//! denial, redirect refusal, size/rate limits, and the shared TLS trust. This
//! gate fails when any other crate:
//!
//! 1. declares a WebSocket client library as a normal or build dependency
//!    (dev-dependencies are fine: tests host fake servers), or
//! 2. names a WebSocket client in production `src/` code (comments, strings,
//!    and `#[cfg(test)]` code are stripped first), or
//!
//! and fails when `ironclaw_network` itself drifts to a different TLS trust
//! from `reqwest` (`rustls-tls-native-roots` only: no `webpki-roots`, no
//! `native-tls`, no default features).
//!
//! Crate discovery goes through the crate inventory, not a directory-name
//! match, so a family move cannot make the scan silently cover nothing; the
//! tests below assert a scan floor for that reason.
#[allow(dead_code)]
mod ratchet_support;

use std::{path::Path, process::Command};

use ratchet_support::{
    crate_directories, production_rust_files, strip_comments_and_strings, workspace_root,
};
use serde_json::Value;

const SANCTIONED_PACKAGE: &str = "ironclaw_network";
const WEBSOCKET_CLIENT_PACKAGE: &str = "tokio-tungstenite";

/// WebSocket client libraries no other package may depend on directly.
const FORBIDDEN_WEBSOCKET_PACKAGES: &[&str] = &[
    "tokio-tungstenite",
    "tungstenite",
    "async-tungstenite",
    "tokio-websockets",
    "fastwebsockets",
    "soketto",
    "websocket",
    "ws",
];

/// Identifiers that mean a production source file is a WebSocket client.
const FORBIDDEN_WEBSOCKET_SYMBOLS: &[&str] = &[
    "tokio_tungstenite",
    "tungstenite::",
    "async_tungstenite",
    "tokio_websockets",
    "fastwebsockets",
    "soketto",
];

/// Minimum number of production `.rs` files the source scan must have read.
/// A scan that resolved no crates would otherwise pass vacuously.
const MIN_SCANNED_PRODUCTION_FILES: usize = 500;

fn cargo_metadata(root: &Path) -> Value {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .output()
        .unwrap_or_else(|error| panic!("failed to run cargo metadata: {error}"));
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata output must be JSON")
}

fn production_dependencies(package: &Value) -> Vec<&Value> {
    package["dependencies"]
        .as_array()
        .map(|dependencies| {
            dependencies
                .iter()
                // `kind: null` is a normal dependency; dev is excluded.
                .filter(|dependency| matches!(dependency["kind"].as_str(), None | Some("build")))
                .collect()
        })
        .unwrap_or_default()
}

/// The first forbidden WebSocket symbol a production source names, if any.
fn websocket_client_symbol(source: &str) -> Option<&'static str> {
    let stripped = strip_comments_and_strings(source);
    FORBIDDEN_WEBSOCKET_SYMBOLS
        .iter()
        .find(|symbol| stripped.contains(**symbol))
        .copied()
}

#[test]
fn only_ironclaw_network_depends_on_a_websocket_client_library() {
    let root = workspace_root();
    let metadata = cargo_metadata(&root);
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata must include packages");
    assert!(
        packages.len() >= 50,
        "cargo metadata returned only {} packages; the scan would be vacuous",
        packages.len()
    );

    let mut violations = Vec::new();
    let mut sanctioned_declares_client = false;
    for package in packages {
        let name = package["name"].as_str().unwrap_or_default();
        for dependency in production_dependencies(package) {
            let dependency_name = dependency["name"].as_str().unwrap_or_default();
            if !FORBIDDEN_WEBSOCKET_PACKAGES.contains(&dependency_name) {
                continue;
            }
            if name == SANCTIONED_PACKAGE && dependency_name == WEBSOCKET_CLIENT_PACKAGE {
                sanctioned_declares_client = true;
            } else {
                violations.push(format!(
                    "{name} depends on WebSocket client `{dependency_name}`; outbound WebSockets \
                     must go through `{SANCTIONED_PACKAGE}`"
                ));
            }
        }
    }
    assert!(
        sanctioned_declares_client,
        "`{SANCTIONED_PACKAGE}` must declare `{WEBSOCKET_CLIENT_PACKAGE}` as its WebSocket client; \
         if it moved, update this gate with the ADR"
    );
    assert!(
        violations.is_empty(),
        "second WebSocket client found:\n{}",
        violations.join("\n")
    );
}

#[test]
fn websocket_tls_trust_matches_reqwest_native_roots() {
    let root = workspace_root();
    let metadata = cargo_metadata(&root);
    let network = metadata["packages"]
        .as_array()
        .and_then(|packages| {
            packages
                .iter()
                .find(|package| package["name"] == SANCTIONED_PACKAGE)
        })
        .expect("ironclaw_network must be a workspace package");
    let dependencies = production_dependencies(network);
    let client = dependencies
        .iter()
        .find(|dependency| dependency["name"] == WEBSOCKET_CLIENT_PACKAGE)
        .expect("ironclaw_network must depend on tokio-tungstenite");
    let features: Vec<&str> = client["features"]
        .as_array()
        .map(|features| features.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        features.contains(&"rustls-tls-native-roots"),
        "tokio-tungstenite must use rustls with native roots like reqwest; features: {features:?}"
    );
    for forbidden in [
        "rustls-tls-webpki-roots",
        "native-tls",
        "native-tls-vendored",
    ] {
        assert!(
            !features.contains(&forbidden),
            "tokio-tungstenite feature `{forbidden}` would give WebSocket a second TLS trust \
             store; features: {features:?}"
        );
    }
    assert_eq!(
        client["uses_default_features"],
        Value::Bool(false),
        "tokio-tungstenite must opt out of default features so the TLS set is explicit"
    );
    let reqwest = dependencies
        .iter()
        .find(|dependency| dependency["name"] == "reqwest")
        .expect("ironclaw_network must own reqwest");
    let reqwest_features: Vec<&str> = reqwest["features"]
        .as_array()
        .map(|features| features.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        reqwest_features.contains(&"rustls-tls-native-roots"),
        "reqwest TLS trust changed; WebSocket TLS parity must be re-decided: {reqwest_features:?}"
    );
}

#[test]
fn no_production_source_outside_ironclaw_network_names_a_websocket_client() {
    let root = workspace_root();
    let mut scanned = 0usize;
    let mut violations = Vec::new();
    for directory in crate_directories(&root) {
        if directory.rsplit('/').next() == Some(SANCTIONED_PACKAGE) {
            continue;
        }
        let src = root.join(&directory).join("src");
        if !src.is_dir() {
            continue;
        }
        for path in production_rust_files(&src) {
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            scanned += 1;
            if let Some(symbol) = websocket_client_symbol(&source) {
                let relative = path.strip_prefix(&root).unwrap_or(&path);
                violations.push(format!(
                    "{} names WebSocket client `{symbol}`; use `{SANCTIONED_PACKAGE}`",
                    relative.display()
                ));
            }
        }
    }
    assert!(
        scanned >= MIN_SCANNED_PRODUCTION_FILES,
        "scanned only {scanned} production files (floor {MIN_SCANNED_PRODUCTION_FILES}); crate \
         discovery likely resolved nothing, so this gate proves nothing"
    );
    assert!(
        violations.is_empty(),
        "WebSocket client used outside the network boundary:\n{}",
        violations.join("\n")
    );
}

#[test]
fn websocket_symbol_scanner_flags_code_and_ignores_comments_and_strings() {
    assert_eq!(
        websocket_client_symbol("use tokio_tungstenite::connect_async;"),
        Some("tokio_tungstenite")
    );
    assert_eq!(
        websocket_client_symbol("let e: tungstenite::Error = todo();"),
        Some("tungstenite::")
    );
    assert_eq!(
        websocket_client_symbol(
            "// tokio_tungstenite is owned by ironclaw_network\nlet name = \"tokio_tungstenite\";"
        ),
        None
    );
    assert_eq!(websocket_client_symbol("fn ordinary() {}"), None);
}
