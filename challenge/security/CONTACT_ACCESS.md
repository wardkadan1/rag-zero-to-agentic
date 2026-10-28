# Contact details: who may read them (SECURITY · final review)

## What exists now: development only

`access.py` reads a candidate's e-mail, phone and links from `chroma_db/contacts/<version>.json`
when **the process** has `CV_CONTACT_ACCESS=granted` and the caller states a purpose.

* The grant belongs to the **process, not to a person**. Anyone, or any agent, that can call the
  app or the MCP server gets the same access. There is no user identity, so the access log says
  *what* was read and *why*, never *who* asked.
* That is acceptable for one student on their own laptop. It is **not** an authorization system.
* Guard rails that are in place:
  * With `RAG_ENV=production`, every read is refused (`denied:development_only`) even when the
    grant is set.
  * The MCP tool `get_contact_details` does not exist for agents unless the operator sets
    `CV_MCP_CONTACT_TOOL=enabled`. It is never registered in production. An agent cannot see or call it.
  * Every attempt is logged in `chroma_db/contact_access.log` (0600) with time, document id,
    decision and purpose. The purpose is masked before it is written: the PII policy, every
    contact value stored for that CV (in any case or spacing), and any 5+ digits. So a purpose
    cannot smuggle contact details into the log.

## Required before any production use: per-user authorization (proposal, not implemented)

1. **Identity.** Every request carries an authenticated user (SSO/OIDC). The app and the MCP server
   verify the token and never accept a user name from the request body or from an agent.
2. **Roles.** `recruiter` may search and read masked CVs. `hiring_contact` may read contact details
   of candidates in a requisition they are assigned to. Agents get a service identity with **no**
   contact permission by default.
3. **Grants, not switches.** A contact read needs a short-lived grant (for example 15 minutes)
   issued per user, per candidate document id, and per purpose code. Purpose codes are a fixed list
   (`interview_scheduling`, `offer`, `reference_check`), not free text. The grant is signed by the
   server, so neither the client nor the model can mint one.
4. **Approval for agents.** If an agent needs contact details, it asks. A human with the role
   approves in the UI, and the grant goes to that human's session, not to the agent's context.
5. **Minimisation.** Return only the requested kind (e-mail *or* phone). Never put contact details
   into prompts, model context, traces or exports.
6. **Audit.** Use an append-only, tamper-evident log (hash chain or WORM storage). Each entry records
   user id, role, document id, purpose code, grant id and decision, never the value. Review it
   regularly and keep it per the retention policy.
7. **Limits.** Rate-limit per user, for example a few candidates per hour, and alert on bulk reads.
8. **Candidate rights.** Candidates' consent and deletion requests remove their contact entry
   from every version (`retention.py`), and later grants for them fail.

Until this exists, deploy without contact access. Keep `CV_CONTACT_ACCESS` unset, keep
`CV_MCP_CONTACT_TOOL` unset, and set `RAG_ENV=production`.
