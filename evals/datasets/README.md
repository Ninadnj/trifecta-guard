# Datasets

| file | purpose | may be edited while tuning rules? |
|---|---|---|
| `heldout.jsonl` | Reported test set. Written and committed **before any detector code existed** (see git history). | **No.** Only additions in a new, separately reported file. |
| `dev.jsonl` | Development set used to write and tune the heuristic rules. | Yes |

Row fields: `id`, `label` (`injection` / `benign`), `source` (where the text would reach an agent:
`web`, `email`, `issue`, `doc`, `code`, `search`, `tool_desc`), `category`, `text`.

Optional `hidden` + `transform` build evasive payloads at load time so the file stays readable:
`{hidden}` in `text` is replaced by `hidden` after applying the transform —
`tags` (Unicode tag characters, invisible in most renderers), `zw` (zero-width spaces between
characters) or `b64` (base64).

Both sets were written by the same author as the rules, so they are **not** an independent
benchmark. They measure regressions and make the trade-offs visible; see the main README for
external benchmarks worth running.
