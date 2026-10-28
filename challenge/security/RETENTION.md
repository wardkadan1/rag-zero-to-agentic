# Privacy and retention policy (SECURITY · Phase 5)

The CVs are real people's data. This is what the pipeline keeps, where, for how long, and how it is
deleted. The index folder `chroma_db/` is owner-only (0700). `python challenge/security/retention.py` shows what is stored now (names and counts only);
`--sweep` deletes what is expired; `--exports` also deletes the app's Verify export.

| What | Where | Holds | Kept | Deleted by |
|---|---|---|---|---|
| Original CV files | `challenge/cvs/` (git-ignored) | everything | as long as the operator keeps them | the operator; never modified by the pipeline |
| Parser staging | a private temp folder (0700, files 0400) | the bytes of one ingestion | during that ingestion only | `sandbox.parse_all`, always (also on errors) |
| Active index version | `chroma_db/` collection named in `ACTIVE.json` | CV text with contact details masked, vectors, claims | until a newer version is active | the next successful build |
| Previous index version | `chroma_db/` (`previous` in `ACTIVE.json`) | the same, one version older | one more build (rollback, readers) | the build after that |
| A version a reader still uses | `chroma_db/readers/<pid>.json` lease | — | while that reader process lives; a live reader renews it every 5 minutes, a lease not renewed for 1 hour protects nothing | the next build after the lease ends |
| Index signing key | `chroma_db/.index_key` (0600) | a random key that signs `ACTIVE.json` | as long as the index folder | the operator (a new key makes enforce readers refuse the old index) |
| Files of deleted versions | Chroma segment folders | old vectors and text | never kept | `retention.sweep`, after every build |
| Contact details | `chroma_db/contacts/<version>.json` (0600) | e-mail, phone, links per document id | exactly as long as their index version | with their version (`retention.sweep`) |
| Contact access log | `chroma_db/contact_access.log` (0600) | time, document id, decision, purpose; never the details | until the operator deletes it | the operator |
| Security report | `challenge/security/quarantine.json` (git-ignored, 0600) | file names, hashes, reason codes; no CV text | overwritten by every ingestion | the next ingestion |
| Decisions, identities | `decisions.json`, `identities.json` (git-ignored) | hashes and decisions only | until the operator changes them | the operator |
| Verify export | `challenge/verify_results.json` (git-ignored, 0600) | questions, histories, prompts, answers, scores and passages, every string through the PII policy | until reviewed | `retention.py --exports` or the operator |

Rules:
* Nothing from the CVs goes into git, logs or reports beyond file names, hashes and reason codes.
* Every text that leaves ingestion (LLM prompts, answers, MCP results, exports) passes the one
  PII policy in `pii.py`; contact details are readable only through `access.py` with the
  operator's authorization (`CV_CONTACT_ACCESS=granted`) and a stated purpose. That grant is
  process-wide and development-only (see `CONTACT_ACCESS.md`); it is refused in production.
* Copies made for evaluation outside the repository must be redacted the same way and deleted
  when the evaluation is finished.
