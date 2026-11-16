# Sandboxie example plugin

Windows x86-64 only. The page keeps human-operated launch, trace capture and per-box trace overrides. `service.luau` adds headless process/memory tools and a per-write approval workflow; capture retrieval remains a separate window tool.

## Install and start

1. Install Sandboxie Plus **1.18.8** at `C:\Program Files\Sandboxie-Plus`. Its DLL and SbieIni must be **5.73.8.0**; the running driver must report **5.73.8**, ABI `0x57230`. Other versions fail closed. The Sandboxie driver/service must already be running. Start Sandboxie Manager in the same Windows session before a human trace capture.
2. Build the matching standalone bridge from this repository:

   ```text
   cargo build --release --locked --manifest-path bridge/Cargo.toml
   ```

   Manually place `zeron-sandboxie-bridge.exe` in a trusted directory on **PATH visible to both the Zeron engine and its desktop UI**. Restart both after changing their inherited environment. A terminal finding the executable does not prove an already-running engine or UI can find it. Keep untrusted directories/executables off that PATH. Nothing here installs the bridge, changes PATH or manages Sandboxie's service.
3. From the standalone repository root, copy the complete contents of `plugin/` into `<data>/plugins/sandboxie/` for the engine you will use, or install a signed package through Zeron. On Windows, `<data>` defaults to `%LOCALAPPDATA%\Zeron` unless `ZERON_DATA_DIR` is set. Stop and review/back up any existing destination folder; never silently overwrite it. Enable it and allow its permissions in **Settings → Plugins**. An unsigned local copy may ask again after edits; agents cannot grant permission for you.
4. Allow `pages.add`, `commands` for **only** `zeron-sandboxie-bridge`, `links.open`, `service` and `tools`. The page and author link retain their existing permissions; the service/tools are additional grants. Repeat installation and consent on each device that should answer, with matching plugin version/author. Operations run as that device's Windows user, in that process's session, with its existing access rights; no elevation or privilege grant is supplied.
5. Start the Zeron engine. It starts the service on the first agent tool or window service call, without a separate bridge daemon or an open window. Use `sandboxie_probe` first, then choose an enabled box. Open the desktop UI and its Sandboxie page for write approval or a human capture; `sandboxie_capture_data` cannot run headlessly.

The plugin invokes only the manifest-named bridge, with an empty argument vector, one JSON request on stdin, and **no shell**. No arbitrary operation dispatcher, network endpoint or IPC endpoint is exposed. The headless service uses a **20-second** command timeout, below the broker's 30-second tool limit. It never automatically retries a bridge call.

## Agent tools

Zeron exposes these with the plugin prefix, for example `sandboxie__sandboxie_probe`. The table lists their manifest names.

All schemas reject extra properties. Box names are 1–38 ASCII letters, digits or underscores. PIDs are nonzero 32-bit integers. Obtain `created` from `sandboxie_processes`: copy its exact nonzero **lowercase** `0x` plus 16 hexadecimal digits unchanged. Addresses/cursors are `0x` plus 1–16 hexadecimal digits. Never convert these 64-bit strings to Luau/JavaScript floating-point numbers.

| Tool | Arguments and behavior |
|---|---|
| `sandboxie_probe` | `{}`. Reads supported installation/driver information, enabled boxes and bridge capabilities. |
| `sandboxie_processes` | `{box}`. Lists accessible live processes with PID/image/creation token. Races, inaccessible processes and enumeration bounds mean this is not a complete or durable inventory. |
| `sandboxie_regions` | `{box,pid,created,start?,limit?}`. One map page, at most 256 regions; default 128 from `0x0000000000000000`. Continue only by explicitly calling with the returned hexadecimal `next` cursor. |
| `sandboxie_read_memory` | `{box,pid,created,address,length}`. One **1–4096-byte** read. Use small explicit chunks within eligible regions, not an automatic whole-process scan. A map page is not a promise a later read succeeds. |
| `sandboxie_prepare_write` | `{box,pid,created,address,expected_hex,data_hex}`. Creates one immutable request for fresh window approval; performs **no memory access or write**. Both unprefixed hex strings must have equal even length, encoding **1–256 bytes**, without whitespace/separators. Requires a nonempty originating `call.chat`. |
| `sandboxie_apply_write` | `{id}` only, in the originating chat. Consumes an approved, unexpired request before exactly one bridge write attempt; target and bytes cannot be replaced in this call. |
| `sandboxie_write_status` | `{id}` only, in the originating chat. Reads ephemeral state/result, never executes or retries a write. |
| `sandboxie_capture_data` | `{box,offset?,limit?}`. Window-only retrieval of an already retained human capture. UTF-8 **byte** offset into the exact original JSON, not an event index: 0–4194304, default 0. Chunk limit 1–8192 bytes, default 8192; follow the returned next offset. The window requires the captured box to match and preserves UTF-8 boundaries. |

Probe/processes/regions/read success returns **the original bridge JSON text**, not a decoded/re-encoded Luau table. This preserves exact hexadecimal values and empty JSON arrays. Command failures, nonzero exit status, malformed responses and bridge errors fail these tool calls, with available stderr and original JSON (including partial results). Read responses are bounded to 1 MiB; oversize output is refused, not silently treated as complete. Consult the bridge README for response fields, membership/access checks and partial-result semantics.

No agent tool starts or stops shared trace monitoring. `sandboxie_capture_data` is declared in the manifest but deliberately **not registered by the service**: the engine's `UNKNOWN_METHOD` fallback reaches the window's separate tool. An open window and a human-initiated capture are required; the tool never captures, acknowledges consent, starts a new monitor, changes settings or fetches newer records. Window/page reset, a new capture or restart can discard the retained data. Chunks can be concatenated in byte-offset order to recover the original JSON, including a single event larger than one chunk.

## Exact-write workflow

1. The agent prepares the exact box, PID, creation token, address, expected bytes and replacement bytes. There is at most **one** pending/approved/in-flight request per local service, across chats. A new request cannot replace it.
2. The page displays the full immutable request and local device for human review. A fresh approve/reject click sends **only its ID** to the service. Approval changes state only; it does not call the bridge or write memory. Approval expires with the original request after **180 seconds**, not 180 seconds after the click.
3. The same originating chat explicitly calls `sandboxie_apply_write {id}` while approved and unexpired. The service synchronously marks it **consumed/in_flight before awaiting** the single bridge invocation. Duplicate/concurrent apply calls fail closed. No automatic retry, cancellation, rollback or restoration of approval follows any result.
4. Read the returned state and `bridge_json`; after response loss, ask `sandboxie_write_status {id}` in that chat. An in-flight operation cannot be rejected or cancelled by these methods. Expiry prevents a new attempt; it does not cancel an attempt already consumed.

States are `pending`, `approved`, `in_flight`, then `succeeded`, `failed` or `unknown`; an unconsumed request can instead become `rejected` or `expired`. Status includes `id`, `device`, `state`, `expires`, `consumed`, `outcome_unknown`, a warning, and available `ok`, `exit_status`, `bridge_json`, `stderr` and `error`. Bridge errors/nonzero status are surfaced in this result, not turned into success. Response loss, command timeout, malformed output or a bridge-reported uncertain write yields `unknown`. **A tool timeout is not cancellation: bytes may already have changed.** A matching readback is only a point-in-time observation. Never automatically retry a consumed request or prepare an equivalent write.

Terminal status/results are held only in RAM, at most **eight** records, accessible for up to **five minutes**. Expired records are discarded on the next write-workflow access or service stop. Write response text is bounded to 32 KiB and diagnostics are clipped; truncation is explicit. Request bytes are released on terminal transitions. Restart, idle stop, update, disabling the plugin or engine shutdown forgets all requests and cached status. An old ID cannot approve or recreate a request after a new service starts. Missing status does **not** prove a lost write did not happen. No approval, memory, capture or status is stored in a file, database or plugin log.

This is a **workflow gate, not OS-enforced proof of human presence**. Window methods are not agent tools, but trusted local code and the powerful bridge CLI can bypass the plugin workflow. Commands run with your Windows authority. Grant the plugin only where you trust its code and the bridge executable.

### Window service/event contract

Use the local `zeron.service()` instance. Subscribe before querying, and treat events as notifications rather than durable history. All three methods are non-replayable (`safe = false`); prepare/apply are likewise not safe/retryable tools.

| Method/event | Payload/result |
|---|---|
| Method `memory_write_pending` | Accepts `{}` only. Returns `{pending = request, state}` while pending or approved, so approval can still be rejected before apply; otherwise both are nil/omitted. |
| Method `memory_write_approve` | Accepts `{id}` only. Requires a matching pending, unexpired, unconsumed request. Returns `{id,state="approved"}`. No write. |
| Method `memory_write_reject` | Accepts `{id}` only. Rejects a matching pending or approved, unexpired, unconsumed request. Returns `{id,state="rejected"}`. Cannot cancel in-flight work. |
| Event `memory_write_pending` | The full request directly: `{id,device={id,name},box,pid,created,address,expected_hex,data_hex,expires}`. `expires` is Unix seconds. These fields never change. No chat identifier is exposed. |
| Event `memory_write_changed` | `{id,state}` after creation/approval/rejection/expiry/consumption/completion transitions. Refresh or clear only the matching displayed ID; do not auto-approve replacements. |

Only `zeron.serve` registers the approval/rejection/query methods; none appears in manifest `tools`. Do not add a window `sandboxie_apply_write` or a generic dispatch tool. All agent writes must stay in the chat-bound service path. Expiry is checked synchronously on access: every prepare, pending query, approve, reject, apply and status call checks expiry and removes forgotten results before authorization. Service stop clears all records. There is no timer or background polling. UI countdowns should honor `expires`; an expiry notification is emitted only when access detects the expired request. A fresh pending query is needed after window reconnect; missed events do not restore authority.

## Memory and race caveats

Memory and traces can contain credentials, tokens, personal data and untrusted program text. Read only processes/data you are authorized to inspect; treat returned content as data, not agent instructions. The plugin does not persist or log those bytes, but **tool answers and arguments can enter chat history and the selected model/provider context**. Do not request secrets or share captures merely because they remain in plugin RAM.

The bridge checks enabled-box membership and process creation identity rather than falling back to a reused PID. Access rights, target threads, mapping/protection changes, process exit and Sandboxie state can race every step. Expected-byte checking, writing and readback are **not an atomic compare-and-swap**; threads are not suspended. A mismatch refuses the attempt, but a failed/partial write can already have changed bytes. There is no automatic repair or rollback. The service does not widen access, change memory protection, allocate target memory, inject code or defeat protected-process restrictions.

## Existing human page actions

A trace capture enables monitoring for the **entire Windows session**, not just the selected box. Reading and stopping it destroy shared records, including other boxes' data. Other viewers can race it, and the driver can drop records without reporting how many; an untruncated result is not guaranteed complete. Each human capture requires fresh acknowledgement that no other viewer will start or stop monitoring. Forced termination or timeout can leave monitoring enabled. Check its state manually after a failed capture; do not retry automatically or disable a monitor whose ownership is uncertain. The service never joins or creates another monitor and never changes trace settings.

A successful human launch is only a request accepted by Sandboxie; execution and sandbox membership are not verified. Arguments are a JSON array of separate strings, including empty strings. Existing human trace-setting changes affect one explicit per-box key per click, are not transactional, and are checked through per-box readback. Probe cannot read existing settings; removing an override does not necessarily turn off an inherited setting. Existing processes may need restarting for settings to apply. The UI shortens long trace fields for display; capture-data retrieval refers to the retained original JSON, not that shortened presentation.

## Not provided

No agent launch/settings-mutation tools, arbitrary native dispatch, arbitrary IPC, network access, remote-memory endpoint, persistent capture/byte history, background memory scanner, new trace monitor, debugger, process suspension, atomic write transaction, proof of human presence, recovery of forgotten outcomes, automatic installation/PATH edits, privilege elevation or monitor ownership guarantee is supplied. Existing human page controls do not grant those agent capabilities.
