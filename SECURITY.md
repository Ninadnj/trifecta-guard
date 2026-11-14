# Security

trifecta-guard reduces risk; it does not make an agent safe to point at hostile content with
unlimited permissions. Read the README's "Threat model and limitations" before relying on it.

**Reporting a bypass.** A payload that gets an obedient agent to exfiltrate fingerprinted private
data *past the taint gate* is a security bug: please open a private advisory on GitHub
(Security → Report a vulnerability). A phrasing that only evades the *heuristic detector* is
expected and welcome as a regular issue or a pull request adding it to `evals/datasets/dev.jsonl`.

**What the guard stores.** `~/.trifecta-guard/sessions/*.json` holds taint flags, hosts seen, and
salted SHA-256 fingerprints of private data, never the data itself. `audit.jsonl` holds decisions,
rule ids, destinations and short excerpts of *flagged untrusted* text; never tool arguments,
payloads or secrets. Set `TRIFECTA_GUARD_HOME` to move both, `runtime.audit = false` to disable
the log.
