#!/usr/bin/env bash
# agentwarden demo. In one terminal: `cargo run`. In another: `./demo.sh`.
#
# NOTE: we use `curl --json` (curl >= 7.82). The common mistake is plain `-d`,
# which sends Content-Type: application/x-www-form-urlencoded; the JSON body
# extractor rejects that with 422 (via the error envelope) before the handler runs.
set -euo pipefail

URL="127.0.0.1:8080/evaluate"

probe() {
  printf '\n$ %s\n=> ' "$1"
  curl -s --json "$1" "$URL"
  printf '\n'
}

probe '{"tool":"bash","command":"rm -rf /","agent":"claude-code"}'              # deny  (prefix)
probe '{"tool":"bash","command":"ls -la","agent":"claude-code"}'                # allow (prefix)
probe '{"tool":"bash","command":"git push origin main","agent":"claude-code"}'  # ask   (regex)
probe '{"tool":"bash","command":"cat secrets.env","agent":"claude-code"}'       # deny  (glob)
probe '{"tool":"bash","command":"sudo reboot","agent":"claude-code"}'           # deny  (shorthand)
probe '{"tool":"bash","command":"whoami","agent":"claude-code"}'                # ask   (default)
