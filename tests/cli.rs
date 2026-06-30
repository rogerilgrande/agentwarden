//! End-to-end test of the compiled binary's `check` subcommand. It runs the real
//! CLI against the repo's `policy.toml` (cargo runs integration tests from the
//! package root) and asserts the decision JSON printed to stdout. This exercises
//! the whole binary: clap parsing, env config, policy load, and the engine.

use std::process::Command;

/// Run `agentwarden check --command <command>` and return its stdout.
fn check(command: &str) -> String {
    // Pin the policy by absolute path and drop any ambient AGENTWARDEN_* so the
    // test does not depend on the caller's environment or working directory.
    let policy = concat!(env!("CARGO_MANIFEST_DIR"), "/policy.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_agentwarden"))
        .args(["check", "--command", command, "--tool", "bash"])
        .env("AGENTWARDEN_POLICY", policy)
        .env_remove("AGENTWARDEN_ADDR")
        .env_remove("AGENTWARDEN_RELOAD_SECS")
        .env_remove("AGENTWARDEN_ADMIN_KEY")
        .output()
        .expect("agentwarden binary runs");
    assert!(
        output.status.success(),
        "check exited with failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout is valid utf-8")
}

#[test]
fn check_denies_a_destructive_command() {
    assert!(check("rm -rf /").contains("\"deny\""));
}

#[test]
fn check_allows_a_listed_safe_command() {
    assert!(check("ls -la").contains("\"allow\""));
}

#[test]
fn check_asks_when_no_rule_matches() {
    assert!(check("whoami").contains("\"ask\""));
}
