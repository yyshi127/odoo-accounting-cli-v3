# Pi multi-turn security design

Status: multi-turn persistence design baseline; not an implemented chat-thread
store or production evidence. The separate FD4 terminal-answer admission
control is implemented and contract-tested, but it is not the complete
multi-turn design below and does not constitute the retained live Pi trace or
95%-selection evidence for the frozen 43-scenario gate.

This design keeps V2 intact and defines a separate V3 chat path. It authorizes
no Odoo write.

## Confirmed baseline

The hardened V3 bridge deliberately starts each Pi turn with:

- an empty conversation context;
- no Pi session ID;
- `--no-session`;
- one short-lived broker session handle delivered over inherited file
  descriptor 3.

Minting and revoking that broker handle for every request is a required
security property. It is not the cause of the missing multi-turn business
context and must not be weakened to add memory.

The retained V2 `sudo_ai_bot` conversation data is not a V3 trust source:

- its conversation is bound to a user but not to a company, database UUID,
  authenticated Web session, authorization epoch, or expiry;
- its Pi session name is predictable from database and record identifiers;
- company changes and later logins can select the same conversation;
- ordinary internal users can create and modify conversation/message records.

Consequently, V2 transcripts may remain visible through the V2 interface but
must not be imported as V3 authority, approval, tool history, Odoo result, or
assistant history.

Authentication session, V3 chat thread, and Pi memory session are three
different concepts. None can substitute for another.

## First production-safe scope

The first V3 multi-turn implementation persists only structured accounting
clarification state. It continues to start a fresh Pi process with
`--no-session` for each turn.

Example state:

```json
{
  "schema": "odoo-accounting-cli-v3-clarification-state.v1",
  "revision": 2,
  "status": "collecting",
  "candidate_capability_id": "acct.bill.vendor_create.v1",
  "known_parameters": {
    "partner_id": 18,
    "accounting_date": "2026-07-30"
  },
  "missing_parameters": [
    "/currency_id",
    "/lines"
  ],
  "last_question_id": "018f80f8-12b8-7e21-a4e3-58beec3a3081"
}
```

These values remain untrusted user-declared business facts. Before persistence,
the V3 gateway must validate the candidate capability, JSON field paths,
parameter types, and completeness against the authenticated capability
registry. Clarification state can never supply identity, company authority,
approval, signing material, release selection, or a business-success claim.

## Separate V3 records

Do not reuse `sudo.ai.conversation` as the authoritative V3 store. Add
release-bound V3 records for:

- chat thread;
- chat turn;
- chat message.

A thread binds at least:

- a random thread UUID;
- Odoo user, active company, database name and UUID;
- channel type and a server-derived channel-session binding;
- authorization epoch;
- active, scope-changed, logged-out, expired, archived, or revoked status;
- idle and absolute expiry;
- clarification revision, canonical JSON, and digest;
- a monotonic turn sequence.

Users may read their permitted V3 records but may not directly create, modify,
or delete authoritative messages or state. Only the controlled V3 gateway
service writes them.

## Public request contract

The Odoo-facing API accepts business input only:

```json
{"thread_id":"server-issued-uuid","client_request_id":"uuid-v4","message":"日期是7月30日，币种美元"}
```

It must reject caller-supplied:

- user, company, database, or allowed-company data;
- provider, model, system prompt, skill, or Pi session selectors;
- conversation transcript;
- approval or signing fields;
- release, registry, binary, configuration, or socket selectors.

`thread_id` is only a record locator. Every turn independently revalidates the
current authenticated user, active company, database, channel session, epoch,
thread status, and expiry.

The same `client_request_id` and identical message return the retained result.
The same ID with different content is a tamper conflict. A per-thread durable
lease permits only one active turn; a second concurrent turn is rejected or
queued according to an explicit product policy.

The hardened Bridge HTTP body remains exactly:

```json
{"message":"..."}
```

Thread, turn, epoch, and clarification bindings travel only through trusted
session state and an internal broker route, never through caller HTTP fields.

## State machines

Thread:

```text
active -> scope_changed | logged_out | expired | archived | revoked
```

A terminal thread cannot resume its old authorization epoch.

Turn:

```text
accepted
  -> context_bound
  -> pi_running
  -> clarification | completed | refused | failed_no_effect | outcome_unknown
  -> reconciled
```

`outcome_unknown` prohibits replay until trusted reconciliation completes.

Clarification:

```text
none -> collecting(revision 1..N) -> ready
     -> operation_prepared | cancelled | expired
```

Approval remains in the existing independent approval authority. Chat text such
as “approve” or “I agree” must not change approval state.

## Trusted Pi event capture

Pi 0.80.6 supports JSON event output for assistant, tool start/end, agent end,
and agent-settled events. Replace print-only capture with strict JSON event
capture before treating a trace as evidence.

The parent process must:

- wait for `agent_settled`, clean end-of-file, and child exit status zero;
- reject missing, duplicate, out-of-order, oversized, or unmatched tool events;
- retain exact tool requests and validated results;
- bind broker dispatch, approval, Odoo receipt, and assistant result;
- generate the trace receipt with a key unavailable to the Pi child.

The trace binds thread, turn, clarification revision, authenticated
user/company/database, provider/model, fixed prompt digest, tool-set digest,
release/registry digests, tool calls/results, Odoo receipts, final assistant
result, and clarification transition.

Pi JSONL, Pi session files, and the assistant's own claims are not authority or
audit evidence.

## Logout, company switch, and concurrency

Logout must revoke the V3 chat scope/epoch before the Web session is destroyed.
Every broker dispatch rechecks that the scope remains valid. A company switch
ends the current scope; the next turn must fail even if the browser missed its
cleanup call.

Revocation cannot retroactively undo a committed Odoo transaction. Its required
boundary is before the next broker tool dispatch.

A browser “sending” flag is not concurrency control. The server uses a durable
thread lease and optimistic clarification revision/digest checks.

## Required negative tests

- Extra hardened `/chat` fields fail with HTTP 400 and no Pi spawn.
- Missing or invalid authenticated broker session fails with HTTP 401 and no
  Pi spawn.
- Other-user, cross-company, cross-database, stale-epoch, expired, archived,
  revoked, and post-logout threads cannot mint a handle or start Pi.
- A predictable V2 Pi session identifier cannot open a V3 thread.
- Reusing a client request ID with changed text is rejected.
- Two concurrent turns cannot both acquire the same thread lease.
- Stale clarification revisions/digests and unknown capability fields fail.
- User-written assistant transcript content has no effect on V3.
- Chat approval text cannot create an approval.
- Missing or inconsistent Pi JSON events fail closed.
- No assistant response may report business success without a verified
  terminal Odoo receipt.
- V2 behavior remains unchanged and the hardened V3 child never receives V2
  tools.

## Deferred optional full transcript memory

Full free-form chat memory is a separate second phase. If required, its Pi
memory ID must be an HMAC over database UUID, user, company, V3 thread, epoch,
and prompt schema. It must use a private V3 session directory, per-thread
durable locking, before/after file hashes held across a different trust
boundary, and a new child process with a new broker handle for every turn.

Pi memory can improve user experience only. It can never restore authority,
approval, or business-success facts.
