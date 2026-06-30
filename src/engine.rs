//! The decision engine: given a policy and a tool call, produce a `Decision`.

use crate::policy::Policy;
use crate::types::{Action, Decision, ToolCall};

/// First applicable rule wins; otherwise the policy's `default` action applies.
#[tracing::instrument(
    skip(policy),
    fields(tool = %call.tool, agent = %call.agent.as_str())
)]
pub(crate) fn evaluate(policy: &Policy, call: &ToolCall) -> Decision {
    let matched = policy.rules.iter().find(|r| r.applies(call));
    let decision = match matched {
        Some(rule) => action_to_decision(rule.action, rule.reason.clone()),
        None => default_decision(policy.default),
    };

    let rule_id = matched.map(|r| r.id);
    tracing::info!(rule = ?rule_id, decision = decision_label(&decision), "evaluated");
    decision
}

/// Build the `Decision` for a matched rule: its own `reason`, or a generic
/// default for that action. `Allow` carries no reason, so it allocates nothing.
fn action_to_decision(action: Action, reason: Option<String>) -> Decision {
    match action {
        Action::Allow => Decision::Allow,
        Action::Deny => Decision::Deny {
            reason: reason.unwrap_or_else(|| "denied by policy".to_owned()),
        },
        Action::Ask => Decision::Ask {
            reason: reason.unwrap_or_else(|| "confirmation required by policy".to_owned()),
        },
    }
}

/// Build the `Decision` when no rule matched, applying the policy `default`.
/// Only this path may say "no matching rule"; a matched rule must never claim it.
fn default_decision(default: Action) -> Decision {
    match default {
        Action::Allow => Decision::Allow,
        Action::Deny => Decision::Deny {
            reason: "no matching rule; denied by default".to_owned(),
        },
        Action::Ask => Decision::Ask {
            reason: "no matching rule; confirmation required".to_owned(),
        },
    }
}

fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Ask { .. } => "ask",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Policy, PolicyFile, sample_policy};

    fn call(command: &str) -> ToolCall {
        ToolCall {
            tool: "bash".into(),
            command: command.into(),
            agent: "claude-code".parse().expect("valid agent name"),
            session: None,
        }
    }

    #[test]
    fn first_match_wins_and_default_applies() {
        let p = sample_policy();
        assert!(matches!(
            evaluate(&p, &call("rm -rf /")),
            Decision::Deny { .. }
        ));
        assert_eq!(evaluate(&p, &call("ls -la")), Decision::Allow);
        assert!(matches!(
            evaluate(&p, &call("git push origin main")),
            Decision::Ask { .. }
        ));
        assert!(matches!(
            evaluate(&p, &call("cat secrets.env")),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            evaluate(&p, &call("sudo reboot")),
            Decision::Deny { .. }
        ));
        // no rule matches -> policy default "ask"
        assert!(matches!(
            evaluate(&p, &call("whoami")),
            Decision::Ask { .. }
        ));
    }

    #[test]
    fn leading_whitespace_is_normalized() {
        let p = sample_policy();
        assert!(matches!(
            evaluate(&p, &call("   rm -rf /")),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn known_limitation_shell_chaining_is_not_parsed() {
        // DOCUMENTED in README's threat model: matching is string-pattern based,
        // not a shell parser, so a chained command starting with an allowed prefix
        // is allowed. This test pins that behavior so a future change is deliberate.
        let p = sample_policy();
        assert_eq!(evaluate(&p, &call("ls; rm -rf /")), Decision::Allow);
    }

    #[test]
    fn known_limitation_naive_deny_is_evaded_by_spacing_or_path() {
        // DOCUMENTED in README's threat model: only leading/trailing whitespace is
        // normalized (trim), so a collapsed double space or an absolute path slips
        // past a "rm -rf" prefix deny and falls through to the default. Pinned so a
        // future change to the matcher is deliberate.
        let p = sample_policy();
        assert!(matches!(
            evaluate(&p, &call("rm  -rf /")),
            Decision::Ask { .. }
        ));
        assert!(matches!(
            evaluate(&p, &call("/bin/rm -rf /")),
            Decision::Ask { .. }
        ));
    }

    #[test]
    fn rules_can_be_scoped_to_a_tool() {
        let file: PolicyFile = toml::from_str(
            r#"
            default = "allow"
            rules = [{ type = "prefix", prefix = "echo", action = "deny", tool = "shell", reason = "z" }]
        "#,
        )
        .expect("test policy parses");
        let p = Policy::compile(file).expect("test policy compiles");

        let as_tool = |tool: &str| ToolCall {
            tool: tool.into(),
            command: "echo hi".into(),
            agent: "claude-code".parse().expect("valid agent name"),
            session: None,
        };
        // The rule is scoped to tool="shell": applies there, not to bash.
        assert_eq!(evaluate(&p, &as_tool("bash")), Decision::Allow);
        assert!(matches!(
            evaluate(&p, &as_tool("shell")),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn matched_ask_rule_without_a_reason_does_not_claim_no_match() {
        let file: PolicyFile = toml::from_str(
            r#"
            default = "allow"
            rules = [{ type = "prefix", prefix = "git push", action = "ask" }]
        "#,
        )
        .expect("test policy parses");
        let p = Policy::compile(file).expect("test policy compiles");
        match evaluate(&p, &call("git push origin main")) {
            Decision::Ask { reason } => {
                assert!(!reason.contains("no matching rule"), "got: {reason}")
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn default_ask_path_does_note_no_matching_rule() {
        let p = sample_policy();
        match evaluate(&p, &call("whoami")) {
            Decision::Ask { reason } => {
                assert!(reason.contains("no matching rule"), "got: {reason}")
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }
}
