//! Policy: the rule types, how they parse from `policy.toml`, the `Matcher`
//! trait, and the `PolicyStore` abstraction with a file-backed implementation.

use std::path::Path;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::Deserialize;

use crate::error::GateError;
use crate::types::{Action, RuleId, ToolCall};

/// Decides whether a rule matches a command string. Stored as `Box<dyn Matcher>`
/// so one `Vec` can hold mixed matcher kinds.
pub(crate) trait Matcher: Send + Sync {
    fn matches(&self, command: &str) -> bool;
}

struct ExactMatch(String);
impl Matcher for ExactMatch {
    fn matches(&self, command: &str) -> bool {
        command == self.0
    }
}

struct PrefixMatch(String);
impl Matcher for PrefixMatch {
    fn matches(&self, command: &str) -> bool {
        command.starts_with(&self.0)
    }
}

struct RegexMatch(regex::Regex);
impl Matcher for RegexMatch {
    fn matches(&self, command: &str) -> bool {
        // Unanchored: matches anywhere in the command. See policy.toml for the
        // documented matching semantics.
        self.0.is_match(command)
    }
}

struct GlobMatch(globset::GlobMatcher);
impl Matcher for GlobMatch {
    fn matches(&self, command: &str) -> bool {
        // Whole-command (anchored) match, the opposite of RegexMatch above.
        // See policy.toml for the documented matching semantics.
        self.0.is_match(command)
    }
}

/// How a rule matches, internally tagged by `type` in TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum RuleKind {
    Exact { command: String },
    Prefix { prefix: String },
    Regex { pattern: String },
    Glob { pattern: String },
}

/// A full rule table: the matcher (`RuleKind`, flattened in), the action, an
/// optional reason, and optional agent/tool scoping.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FullRule {
    #[serde(flatten)]
    kind: RuleKind,
    action: Action,
    #[serde(default)]
    reason: Option<String>,
    /// If set, the rule applies only to calls from this agent / tool.
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    tool: Option<String>,
}

/// One entry in the `rules` list. `#[serde(untagged)]` is a whole-enum attribute,
/// so the tagged `RuleKind` and the bare-string shorthand can't live in one enum;
/// this outer wrapper tries `Full` (a table) first, then `DenyPrefix` (a string).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum RuleSpec {
    Full(FullRule),
    DenyPrefix(String),
}

/// The on-disk policy: a default action plus an ordered list of rules.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PolicyFile {
    #[serde(default = "default_action")]
    default: Action,
    #[serde(default)]
    rules: Vec<RuleSpec>,
}

fn default_action() -> Action {
    Action::Ask
}

/// A compiled rule: matcher built, regex/glob already validated.
pub(crate) struct Rule {
    pub(crate) id: RuleId,
    matcher: Box<dyn Matcher>,
    pub(crate) action: Action,
    pub(crate) reason: Option<String>,
    agent: Option<String>,
    tool: Option<String>,
}

impl Rule {
    /// True when the optional agent/tool scope matches and the matcher matches
    /// the (whitespace-trimmed) command.
    pub(crate) fn applies(&self, call: &ToolCall) -> bool {
        self.tool.as_deref().is_none_or(|t| t == call.tool)
            && self
                .agent
                .as_deref()
                .is_none_or(|a| a == call.agent.as_str())
            && self.matcher.matches(call.command.trim())
    }
}

/// A compiled policy ready to evaluate.
pub(crate) struct Policy {
    pub(crate) default: Action,
    pub(crate) rules: Vec<Rule>,
}

impl Policy {
    /// Compile an on-disk `PolicyFile`, validating every regex/glob up front so a
    /// bad pattern fails at load time, not on a request.
    pub(crate) fn compile(file: PolicyFile) -> Result<Self, GateError> {
        let rules: Vec<Rule> = file
            .rules
            .into_iter()
            .enumerate()
            .map(|(i, spec)| compile_rule(RuleId(i as u32), spec))
            .collect::<Result<_, _>>()?;

        let denies = rules.iter().filter(|r| r.action == Action::Deny).count();
        tracing::info!(
            total = rules.len(),
            denies,
            allow_or_ask = rules.len() - denies,
            "policy compiled"
        );

        Ok(Policy {
            default: file.default,
            rules,
        })
    }
}

fn compile_rule(id: RuleId, spec: RuleSpec) -> Result<Rule, GateError> {
    let (kind, action, reason, agent, tool) = match spec {
        RuleSpec::Full(f) => (f.kind, f.action, f.reason, f.agent, f.tool),
        // An empty deny-prefix would match every command (deny-all), almost
        // always a mistake, so the guarded arm rejects it.
        RuleSpec::DenyPrefix(p) if p.trim().is_empty() => {
            return Err(GateError::EmptyRule { id: id.0 });
        }
        RuleSpec::DenyPrefix(p) => {
            let reason = format!("matched deny-list shorthand {p:?}");
            (
                RuleKind::Prefix { prefix: p },
                Action::Deny,
                Some(reason),
                None,
                None,
            )
        }
    };

    Ok(Rule {
        id,
        matcher: build_matcher(id, kind)?,
        action,
        reason,
        agent,
        tool,
    })
}

fn build_matcher(id: RuleId, kind: RuleKind) -> Result<Box<dyn Matcher>, GateError> {
    Ok(match kind {
        RuleKind::Exact { command } => Box::new(ExactMatch(command)),
        RuleKind::Prefix { prefix } => Box::new(PrefixMatch(prefix)),
        RuleKind::Regex { pattern } => Box::new(RegexMatch(
            regex::Regex::new(&pattern)
                .map_err(|source| GateError::BadRegex { id: id.0, source })?,
        )),
        RuleKind::Glob { pattern } => {
            let glob = globset::Glob::new(&pattern)
                .map_err(|source| GateError::BadGlob { id: id.0, source })?;
            Box::new(GlobMatch(glob.compile_matcher()))
        }
    })
}

/// The source of the active policy. An async trait so the backing store can vary
/// (file, mock, …). `#[async_trait]` is kept deliberately: native async-fn-in-traits
/// is stable, but we need `Arc<dyn PolicyStore>` (not dyn-compatible natively),
/// `mockall::automock`, and `Send` futures for `tokio::spawn`.
/// (`#[automock]` must sit above `#[async_trait]`.)
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub(crate) trait PolicyStore: Send + Sync {
    /// The currently-active policy (cheap: clones an `Arc`).
    async fn current(&self) -> Arc<Policy>;
    /// Reload from the backing source; returns the new rule count.
    async fn reload(&self) -> Result<usize, GateError>;
}

/// A `PolicyStore` backed by a TOML file, hot-swappable at runtime.
pub(crate) struct FilePolicyStore {
    path: std::path::PathBuf,
    // Readers (handlers) and a writer (the reload daemon) share this, so it needs
    // shared ownership + interior mutability. `std::sync::RwLock` (not tokio's) is
    // correct: the guard is never held across an `.await`. `arc_swap::ArcSwap` is
    // the lock-free read-mostly alternative.
    current: RwLock<Arc<Policy>>,
}

impl FilePolicyStore {
    pub(crate) async fn load(path: std::path::PathBuf) -> Result<Arc<Self>, GateError> {
        let policy = Self::read_and_compile(&path).await?;
        Ok(Arc::new(Self {
            path,
            current: RwLock::new(Arc::new(policy)),
        }))
    }

    async fn read_and_compile(path: &Path) -> Result<Policy, GateError> {
        let text = tokio::fs::read_to_string(path)
            .await
            .map_err(|source| GateError::PolicyIo {
                path: path.display().to_string(),
                source,
            })?;
        let file: PolicyFile = toml::from_str(&text)?;
        Policy::compile(file)
    }
}

#[async_trait]
impl PolicyStore for FilePolicyStore {
    async fn current(&self) -> Arc<Policy> {
        // Guard dropped at the end of this expression, never held across `.await`.
        Arc::clone(&self.current.read().expect("policy lock poisoned"))
    }

    async fn reload(&self) -> Result<usize, GateError> {
        let policy = Self::read_and_compile(&self.path).await?;
        let n = policy.rules.len();
        *self.current.write().expect("policy lock poisoned") = Arc::new(policy);
        Ok(n)
    }
}

/// A small policy used across unit tests in several modules.
#[cfg(test)]
pub(crate) fn sample_policy() -> Policy {
    let file: PolicyFile = toml::from_str(
        r#"
        default = "ask"
        rules = [
          "sudo",
          { type = "prefix", prefix = "rm -rf",        action = "deny",  reason = "destructive" },
          { type = "glob",   pattern = "cat *.env",    action = "deny",  reason = "secrets" },
          { type = "regex",  pattern = "^git\\s+push", action = "ask",   reason = "network" },
          { type = "prefix", prefix = "ls",            action = "allow" },
        ]
    "#,
    )
    .expect("sample policy parses");
    Policy::compile(file).expect("sample policy compiles")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_deny_prefix_is_rejected() {
        let file: PolicyFile =
            toml::from_str("default = \"ask\"\nrules = [\"\"]\n").expect("test policy parses");
        assert!(matches!(
            Policy::compile(file),
            Err(GateError::EmptyRule { .. })
        ));
    }

    #[test]
    fn bad_regex_is_rejected_at_compile() {
        let file: PolicyFile =
            toml::from_str("rules = [{ type = \"regex\", pattern = \"(\", action = \"deny\" }]")
                .expect("test policy parses");
        assert!(matches!(
            Policy::compile(file),
            Err(GateError::BadRegex { .. })
        ));
    }

    #[test]
    fn bad_glob_is_rejected_at_compile() {
        let file: PolicyFile =
            toml::from_str("rules = [{ type = \"glob\", pattern = \"[\", action = \"deny\" }]")
                .expect("test policy parses");
        assert!(matches!(
            Policy::compile(file),
            Err(GateError::BadGlob { .. })
        ));
    }

    #[test]
    fn invalid_agent_name_is_rejected_on_deserialize() {
        let bad: Result<ToolCall, _> =
            serde_json::from_str(r#"{"tool":"bash","command":"ls","agent":"Bad Name!"}"#);
        assert!(bad.is_err());
    }
}
