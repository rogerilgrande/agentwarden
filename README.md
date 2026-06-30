# agentwarden

A miniature **AI-agent tool-call policy gate**, written in Rust. An agent's proposed
action is sent to the gate, which checks it against a hot-reloadable policy and
returns **`allow` / `deny` / `ask`**, the *decision* layer of an agent safety harness:
the policy decision only, not kernel-level sandboxing or execution.

## Why this exists

agentwarden is a focused demo in idiomatic async Rust. I designed and
scoped it, used Claude Code to scaffold and iterate, and reviewed and refined every file,
applying patterns I've worked with professionally (axum, Tokio, serde, trait-based design).
It deliberately stops at the policy decision and leaves kernel-level enforcement out of scope.

## Quickstart

```bash
# one-time: install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && . "$HOME/.cargo/env"

cargo run            # serve on 127.0.0.1:8080
./demo.sh            # in another terminal: fire the example calls
cargo test           # unit + async (tokio) + HTTP (tower oneshot) + mockall + CLI integration tests
cargo clippy --all-targets
```

## Layout

```
src/
  main.rs     thin binary: starts the Tokio runtime, calls agentwarden::run()
  lib.rs      library root: module list + the CLI (clap) and run()/check()/lint() dispatch
  config.rs   env-var configuration (fails loudly on a malformed value)
  server.rs   axum service, handlers, ValidatedJson extractor, reload daemon, shutdown
  engine.rs   the pure decision function
  policy.rs   rule types, parsing, the Matcher trait, and the PolicyStore abstraction
  error.rs    GateError + its HTTP mapping
  types.rs    validated newtypes, request/response types
```

## HTTP API

```bash
# Use `curl --json` (not plain `-d`, whose form-encoding the JSON extractor rejects with 422).
curl --json '{"tool":"bash","command":"rm -rf /","agent":"claude-code"}' 127.0.0.1:8080/evaluate
# => {"decision":"deny","reason":"destructive filesystem command"}
```

| Method & path     | What it does |
|-------------------|--------------|
| `POST /evaluate`  | Evaluate a tool call → `{"decision":"allow\|deny\|ask", "reason"?}`. Invalid input returns `422` with `{"error": ...}` |
| `POST /reload`    | Force a policy reload. `403` unless `AGENTWARDEN_ADMIN_KEY` is set; then requires a matching `x-admin-key` header (compared in constant time) |
| `GET  /healthz`   | Liveness check |

A background daemon also reloads `policy.toml` on an interval, so editing the file takes
effect with no restart (a bad file is logged and the previous good policy stays active).

## CLI

```bash
cargo run -- check --command "rm -rf /"   # one-shot eval, prints decision JSON
cargo run -- lint                         # validate policy.toml, print rule count
cargo run -- serve                        # explicit form of the default
```

## Configuration (env vars over defaults)

| Var | Default | Meaning |
|-----|---------|---------|
| `AGENTWARDEN_POLICY`      | `policy.toml` | policy file path |
| `AGENTWARDEN_ADDR`        | `127.0.0.1:8080` | listen address |
| `AGENTWARDEN_RELOAD_SECS` | `5` | hot-reload interval; `0` disables the reload daemon |
| `AGENTWARDEN_ADMIN_KEY`     | _(unset)_ | enables and protects `POST /reload` |

A malformed value (e.g. an unparseable `AGENTWARDEN_ADDR`) is a startup error, not a
silent fallback to the default.

## Policy file

First matching rule wins; otherwise the `default` action applies. A rule is either a
bare string (deny-prefix shorthand) or a table tagged by `type`
(`exact` / `prefix` / `regex` / `glob`), optionally scoped with `agent = "..."` /
`tool = "..."`. See [`policy.toml`](./policy.toml) for the matcher semantics.

## Threat model: read before trusting it

agentwarden is the **decision** layer, and matching is **string-pattern based, not a shell
parser**. It assumes it is given a single, already-normalized command, and it is **not**
a boundary against an adversarial or obfuscated command string. Known limitations (pinned
by tests so changes are deliberate):

- **Command chaining is not parsed:** `ls; rm -rf /` starts with the allowed `ls` prefix
  and is therefore allowed. Same for `&&`, `|`, `$(...)`, backticks, newlines.
- **Only leading/trailing whitespace is normalized:** `rm  -rf /` (collapsed double
  space) or `/bin/rm -rf /` (absolute path) can evade a naive `rm -rf` deny.

Treat the gate as defense-in-depth over a *cooperative* agent, paired with real
enforcement. Which brings us to:

## What this deliberately is **not**

Production-grade agent harnesses enforce in the kernel (e.g. Landlock on Linux, Seatbelt
on macOS). agentwarden stops at the **decision**; it does not sandbox or execute anything.
That boundary is intentional: the decision layer is the clean, self-contained build.
