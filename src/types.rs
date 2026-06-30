//! Core data types: validated newtypes, the request (`ToolCall`), the rule
//! outcome (`Action`), and the API response (`Decision`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::GateError;

/// A validated agent name, e.g. `"claude-code"`: non-empty, ASCII lowercase /
/// digits / `-`. Validating in `TryFrom` (and on deserialize) means any
/// `AgentName` that exists is already known-good, so nothing downstream re-checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct AgentName(String);

impl AgentName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AgentName {
    type Error = GateError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let ok = !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if ok {
            Ok(AgentName(s))
        } else {
            Err(GateError::InvalidAgent(s))
        }
    }
}

impl FromStr for AgentName {
    type Err = GateError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AgentName::try_from(s.to_owned())
    }
}

/// A validated, non-empty session id (request metadata, echoed into the evaluate trace).
/// "No session" is expressed by omitting the field (`None`); an explicit empty string is
/// treated as malformed input and rejected, like any other bad field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct SessionId(String);

impl TryFrom<String> for SessionId {
    type Error = GateError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            Err(GateError::InvalidSession(s))
        } else {
            Ok(SessionId(s))
        }
    }
}

/// A rule's identifier: its index in the policy. Not validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuleId(pub(crate) u32);

/// A secret string. `Debug` is hand-written to redact the value, and the type
/// deliberately does not implement `Display`/`Serialize`/`Deref`, so the secret
/// can only be read through the explicit, greppable [`AdminKey::expose`].
#[derive(Clone)]
pub(crate) struct AdminKey(String);

impl AdminKey {
    pub(crate) fn new(s: String) -> Self {
        AdminKey(s)
    }

    /// Borrow the raw secret. Kept explicit so every read site is auditable.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdminKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AdminKey(***)")
    }
}

/// The proposed tool call an agent wants to make (the request body).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ToolCall {
    pub(crate) tool: String,
    pub(crate) command: String,
    pub(crate) agent: AgentName,
    #[serde(default)]
    pub(crate) session: Option<SessionId>,
}

/// A rule's outcome. Distinct from [`Decision`]: `Action` is what a *rule*
/// declares; `Decision` is what the *API* returns and additionally carries a
/// human-readable reason. See `engine::action_to_decision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Allow,
    Deny,
    Ask,
}

/// The gate's verdict (the response body), serialized as an internally-tagged
/// enum, e.g. `{"decision":"deny","reason":"..."}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub(crate) enum Decision {
    Allow,
    Deny { reason: String },
    Ask { reason: String },
}
