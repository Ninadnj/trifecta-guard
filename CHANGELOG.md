# Changelog

## 0.1.0 — 2026-11-14

First release.

* Heuristic injection detector: 80 rules in 12 categories, combination scoring, discussion and
  negation damping, Unicode tag / zero-width / bidi decoding, NFKC fold pass, base64 payloads.
* Sanitizer: invisible-character stripping, markdown image defanging, paragraph redaction with
  quarantine fallback, optional spotlighting.
* Taint gate: per-session clean / tainted / compromised state, salted private-data fingerprints
  (tokens, short env values, 8-word shingles) matched through URL-encoding and base64, attacker-
  introduced destinations, download-and-execute, protected writes.
* Claude Code hooks (`install claude-code`), MCP stdio proxy with tool-poisoning filter, CLI,
  JSONL audit log, TOML policy.
* Evaluation: dev and held-out detection sets (held-out committed first), 20 end-to-end scenarios
  across four arms, reproducibility check in CI.
