# Sandboxie bridge

Standalone x86-64 Windows command for Sandboxie Plus 1.18.8, installed at `C:\Program Files\Sandboxie-Plus`. The DLL and SbieIni file versions must be 5.73.8.0; the running driver must report 5.73.8 and ABI `0x57230`. Other versions fail closed. This tool does not install itself, alter PATH, manage the Sandboxie service, or register a session leader.

Build from the repository root:

```text
cargo build --release --locked --manifest-path bridge/Cargo.toml
```

The resulting `bridge/target/release/zeron-sandboxie-bridge.exe` (from the repository root) can be copied manually to a trusted directory on PATH inherited by both Zeron's desktop UI and engine; restart both after changing PATH. The bridge is an independent Cargo workspace.

## Protocol

Each invocation reads one UTF-8 JSON document from stdin until EOF, performs one operation, prints one JSON object followed by a newline, and exits. Requests are limited to 65,536 bytes. Exit code 0 means `ok:true`; exit code 1 means `ok:false` or output failure. Stdout contains protocol data only. No shell, persistent server, background capture or automatic mutation retry is used. Fields not defined by the operation, duplicate operation fields, incorrect JSON types and trailing documents are rejected. Optional request fields may be omitted, not supplied as `null`.

In the exact response shapes below, `boolean`, `string` and `u32` denote JSON booleans, strings and unsigned 32-bit integers; `null` is literal JSON null. `hex64` denotes a canonical string matching `0x[0-9a-f]{16}`. All native 64-bit addresses, sizes, cursors, FILETIMEs and reported native byte counts are strings, never JSON numbers. The existing trace `time` field remains numeric Unix milliseconds for caller compatibility; `filetime` preserves the original timestamp exactly. Input `address` and `start` accept a lowercase `0x` prefix followed by 1–16 ASCII hexadecimal digits, including uppercase digits. Input `created` must be nonzero and already canonical. Byte payloads have no prefix: outputs are exact lowercase hex, and write inputs accept either digit case. Generic request, version, box and identity failures return exactly `{"ok":false,"error":string}` before any memory write. Validated `write_memory` requests instead retain their operation response for handle/region/expected-byte refusals. Such refusals do not attempt a memory write.

```json
{"op":"probe"}
```

Returns `ok`, `version`, `driver_version`, enabled `boxes` available to the current account, `capabilities` and the monitor warning. `version` is the pinned Plus release, while `driver_version` is read from the installed driver. Existing capability fields remain; new fields advertise `processes`, `regions`, `read_memory`, `write_memory`, `read_memory_max_bytes:4096`, `write_memory_max_bytes:256`, `memory_requires_created:true`, `memory_current_session_only:true` and `write_requires_external_approval:true`. The last field is a caller requirement, not an approval mechanism implemented by this CLI.

## Process and memory operations

These are explicit one-shot operations, not live monitoring. They select only a currently enabled box available to the current account, in the bridge's current Windows session. No process is suspended. Results are point-in-time observations, not a consistent snapshot.

The bridge opens one real process handle and retains that same handle throughout each operation. It never reopens a PID after an identity failure. `GetProcessId`, `GetProcessTimes` creation and exit times, and `GetExitCodeProcess` check the held handle. Each PID-based `SbieApi_QueryProcess` membership query is bracketed by same-handle live/creation checks; both Sandboxie's reported session and Win32 `ProcessIdToSessionId` must match the bridge's session. Memory operations check identity/membership before and after access, with another check and region validation before a write. A failed post-access check suppresses read/region data; after an attempted write it preserves the attempt/count/error metadata, withholds readback bytes and reports uncertainty. These checks reduce PID-reuse errors but cannot make membership queries, target threads, protection changes or process exit atomic with access.

No privileges are enabled, and `SeDebugPrivilege`, Sandboxie's privileged process-opening API and all-access handles are never used. Listing requests `PROCESS_QUERY_LIMITED_INFORMATION`; regions request `PROCESS_QUERY_INFORMATION`; reads add `PROCESS_VM_READ`; writes additionally add `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`. Access denied, inaccessible or already-exited processes are not bypassed. A process can exit immediately after the final check.

### processes

Exact request, with no optional fields:

```json
{"op":"processes","box":"DefaultBox"}
```

Exact operation response shape:

```text
{"ok":boolean,"box":string,"session":u32,"processes":[{"pid":u32,"image":string,"created":hex64}],"truncated":boolean,"inaccessible":u32,"error":string|null,"warning":string}
```

Windows Toolhelp supplies candidate PIDs; `SbieApi_EnumProcessEx` is never called and its array ABI is not assumed. Only live, same-session PIDs attributed by `SbieApi_QueryProcess` to the selected box appear. `image` is Sandboxie's image name, not a Toolhelp snapshot name or guessed path. `created` is the exact `GetProcessTimes` creation FILETIME from the held handle; pass it unchanged on subsequent memory requests. At most 512 results and 65,536 inspected snapshot entries are supported. Reaching either cap conservatively sets `truncated:true`. Enumeration errors return partial results with `ok:false`, `truncated:true` and `error`.

`inaccessible` counts inspected snapshot candidates that could not be safely inspected or attributed, not confirmed members of the selected box. Their PIDs, names and individual errors are withheld; non-box process details are never returned. `ok:true` does not mean there were no inaccessible entries or no truncation. A missing process can be exited, inaccessible, outside the selected box/session or beyond a cap.

### regions

Exact request; `start` and `limit` are the only optional fields:

```json
{"op":"regions","box":"DefaultBox","pid":1234,"created":"0x01dc000000000000","start":"0x0000000000000000","limit":128}
```

`pid` must be nonzero. Omitting `start` selects zero; omitting `limit` selects 128. `limit` must be an integer from 1 through 256. `start` must be page-aligned and within `GetNativeSystemInfo` application-address bounds; malformed, overflowing, misaligned, out-of-bounds or initially unqueryable cursors are refused. The first result is the full native region covering `start`, so its `base` can precede `start`. Use the returned `next` unchanged to request another page with the same PID and creation token.

Exact operation response and region shapes:

```text
{"ok":boolean,"box":string,"pid":u32,"created":hex64,"start":hex64,"limit":u32,"regions":[region],"complete":boolean,"truncated":boolean,"next":hex64|null,"error":string|null}
region = {"base":hex64,"size":hex64,"allocation_base":hex64,"state":u32,"state_name":string|null,"protect":u32,"protect_name":string|null,"allocation_protect":u32,"type":u32,"type_name":string|null,"readable":boolean,"guard":boolean,"executable":boolean,"write_eligible":boolean}
```

`VirtualQueryEx` supplies every range and native numeric state/protection/type. Size and cursor arithmetic is checked for overflow and forward progress. `next` is the exclusive end of the last emitted range; it is null when the queryable address-space end is reached. One bounded look-ahead query can detect that end at a page limit. `complete:true` means the walk reached that end, not that it captured a stable address-space snapshot. `truncated:true` means another page is needed or an enumeration error interrupted the walk. Query errors return `ok:false` and any validated partial regions unless the final identity/membership check fails. A later mapping change can invalidate a formerly valid cursor.

Known state names are `MEM_COMMIT`, `MEM_RESERVE`, `MEM_FREE`; known type names are `MEM_PRIVATE`, `MEM_MAPPED`, `MEM_IMAGE`. `protect_name` names the known low-byte `PAGE_*` base protection only for committed memory. Unknown names are null. Windows leaves some fields undefined for free or reserved memory: raw values are preserved, not interpreted as meaningful protection or allocation metadata. Classification booleans are predicates on committed native attributes, not guarantees that a later access will succeed. `guard` tests `PAGE_GUARD`; `executable` tests the four standard execute protection bits. `readable` requires a known readable base protection, with only the known `PAGE_NOCACHE`/`PAGE_WRITECOMBINE` modifiers permitted and no guard. `write_eligible` requires private committed memory with `Protect` exactly `PAGE_READWRITE`; cache or unknown modifiers are refused for writes. No object names, mapped file contents or process bytes are fetched by this operation.

### read_memory

Exact request, with no optional fields:

```json
{"op":"read_memory","box":"DefaultBox","pid":1234,"created":"0x01dc000000000000","address":"0x0000000000010000","length":64}
```

`length` must be an integer from 1 through 4096. The complete range must be inside native application-address bounds and within one currently committed readable non-guard `VirtualQueryEx` region. Crossing a region is refused, even if the next region is also readable. There is exactly one `ReadProcessMemory` call, no protection change, retry, file or persistence.

Exact operation response shape:

```text
{"ok":boolean,"box":string,"pid":u32,"created":hex64,"address":hex64,"length":u32,"win32_success":boolean,"win32_error":u32|null,"reported_count":hex64,"count":u32,"complete":boolean,"partial":boolean,"data_hex":string,"error":string|null}
```

`reported_count` is the exact native bytes-read count. `count` is the number of initialized bytes actually returned, and `data_hex` has exactly `count * 2` characters. A short or failed read is not successful: `ok` and `complete` require a true Win32 BOOL and the entire requested count. `partial` means some but fewer than the requested bytes were obtained. A failed BOOL with a full reported count still has `ok:false` and `complete:false`, even though `partial:false`. `win32_error` is captured immediately on a false BOOL; null on a true BOOL. Zero bytes produce an empty string. An impossible reported count larger than the request returns no bytes, `count:0`, the exact `reported_count`, and an error rather than silently clipping. A failed final identity/membership check returns the generic error response without disclosing any bytes.

A caller can make a bounded memory-dump export by first paging `regions`, then explicitly requesting readable chunks no larger than 4096 bytes, never crossing a region, retaining addresses, counts and errors. This bridge writes no export files. Such chunks are raw bytes, not a Windows `.dmp` file, crash dump, complete process dump, atomic snapshot or guaranteed reconstruction; regions and bytes can change between calls, and inaccessible ranges remain gaps. Never substitute zero-fill for failed reads.

### write_memory

Exact request, with no optional fields:

```json
{"op":"write_memory","box":"DefaultBox","pid":1234,"created":"0x01dc000000000000","address":"0x0000000000010000","expected_hex":"01020304","data_hex":"05060708"}
```

Both payloads must be valid unprefixed even-length ASCII hex encoding the same 1–256 bytes. The entire range must currently be within one committed, private, non-guard, non-executable region whose `Protect` is exactly `PAGE_READWRITE`. Identity/membership and the region are rechecked before writing. The bridge reads the expected bytes and requires a full successful exact match immediately before one `WriteProcessMemory` call. A mismatch or incomplete expected-byte read prevents that call. This compare-then-write is not atomic against target threads or mapping/protection changes; it is not compare-and-swap.

Exact operation response shape after request/box/version validation:

```text
{"ok":boolean,"box":string,"pid":u32,"created":hex64,"address":hex64,"length":u32,"attempted":boolean,"expected_matched":boolean|null,"win32_success":boolean|null,"win32_error":u32|null,"written":u32|null,"written_reported":hex64|null,"readback":readback|null,"verified":boolean,"uncertain":boolean,"identity_error":string|null,"error":string|null,"warning":string}
readback = {"win32_success":boolean,"win32_error":u32|null,"reported_count":hex64,"count":u32,"complete":boolean,"partial":boolean,"data_hex":string|null,"error":string|null,"matches":boolean|null}
```

`attempted` means the single `WriteProcessMemory` call was made. Before it, write BOOL/count/error/readback fields are null; `expected_matched` is null if a complete expected-byte read was unavailable, false on mismatch and true on an exact match. The Win32 BOOL, immediate failure `GetLastError`, and reported bytes-written count are independently inspected. `written_reported` is the exact native count; `written` is that count only when within the requested length, otherwise null with an explicit error. A failed or short write may already have modified bytes and never returns `ok:true`.

Same-handle readback is always attempted after `WriteProcessMemory`, even if the write BOOL is false or reports zero/partial bytes. Its read metadata has the same meaning as `read_memory`, except that `count` still records obtained bytes when disclosure is withheld. `matches` is null unless the readback is complete and the final identity/membership check succeeds. If that final check fails, `identity_error` explains it and readback `data_hex` is null; attempt/BOOL/count metadata remains. `ok:true` and `verified:true` require a true write BOOL, the full written count, a full matching readback and successful final identity/membership checks. `uncertain:true` means an attempted write did not meet all of those observations; a false value does not promise atomicity, future persistence or application correctness. Target threads can change bytes even during a successful readback.

There is no `VirtualProtectEx`, allocation, injection, thread control, privilege escalation, automatic retry or rollback. The bridge does not suppress, kill or restart target processes. A process may crash or corrupt its own state after any accepted write; a failed write or later timeout does not mean nothing changed. Inspect the full result, never blindly repeat or roll back an uncertain write.

This is a powerful local CLI, not an authorization boundary: it has no approval prompt and stdin can request modification directly with the user's existing OS rights. The plugin service separately requires explicit human approval for every exact write, including selected box, PID, creation token, address and both byte payloads; the bridge itself does not enforce that workflow. Listing, reading or tracing is not consent to writing, approval must not be reused, and a failed command must not trigger automatic approval reuse/retry. Memory, raw records and tag payloads can expose credentials, private paths, network data and other secrets. Nothing is intentionally persisted or sent by this bridge, but the caller can log or retain stdout; treat it as sensitive. No network or IPC sending/export protocol has been added.

## Existing operations

```json
{"op":"launch","box":"DefaultBox","executable":"C:\\Windows\\System32\\notepad.exe","args":[]}
```

The box must match the current enabled box list. The executable must resolve to a regular `.exe` file on a local drive. Relative paths, UNC paths, mapped network drives, device syntax and alternate data streams are rejected. The resolved launch path must fit the legacy Win32 `MAX_PATH` limit and cannot contain trailing-dot/space components, reserved device names or reparse points. Paths whose directory entries cannot be pinned, whose file identity cannot be read, or whose ordinary Win32 reopening differs from the original open file are rejected. The bridge compares the 128-bit file ID and volume serial of the original handle with a fresh ordinary Win32 open, holding both file handles and the resolved path entries without write/delete sharing until Sandboxie returns. An input alias may resolve to a safe launch path, but reparse points in that resolved path are rejected. At most 128 arguments and 8,190 total UTF-16 command-line units are supported. Windows argument quoting preserves empty arguments, spaces, quotes and trailing backslashes.

Launch calls `SbieDll_RunSandboxed` directly. Its response includes `requested:true`, `verified:false`, `pid` and a warning. Success means only that Sandboxie accepted the launch request; it does not prove the process survived initialization, executed its target code, or remained sandboxed. Process and thread handles are closed. The bridge neither waits for nor kills the requested application. Sandboxie itself may start its installed manager or support processes as part of normal initialization.

```json
{"op":"trace","box":"DefaultBox","seconds":3,"exclusive":true}
```

`seconds` must be an integer from 1 through 15. Every capture requires explicit `exclusive:true`: the caller must explain and obtain acknowledgement of the shared-monitor warning before sending it. No consent is remembered between invocations. An already-enabled monitor is refused without reading records or changing its state. A per-Windows-session named mutex prevents overlapping bridge captures.

A Sandboxie manager/session leader must already exist in the same Windows session. The bridge checks enable readback and fails rather than claiming an empty capture succeeded if the driver did not enable monitoring. Normal Sandboxie Manager startup or the first sandbox launch can establish this session. The bridge does not start a manager or change the session leader itself.

The response retains `ok`, `box`, `events`, `truncated`, `warning`, `error` and `cleanup_error`. Each event retains numeric `time` as Unix UTC milliseconds, `pid`, `tid`, raw numeric Sandboxie `type` including flags, and `data` as an array of strings. It adds exact raw `filetime`, `record_hex`, `data_utf16_valid`, `decoded_type` and `tags`:

```text
event = {"time":number,"pid":u32,"tid":u32,"type":u32,"data":[string],"filetime":hex64,"record_hex":string,"data_utf16_valid":boolean,"decoded_type":decoded_type,"tags":[tag]}
decoded_type = {"type_id":u32,"type_name":string|null,"disposition":u32,"result":u32,"flags":[string],"unknown_flags":u32}
tag = {"id":u32,"name":string|null,"length":u32,"data_hex":string}
```

`record_hex` is the exact unmodified GET2 record payload, starting with the original eight FILETIME bytes and including all type/PID/TID/string/sentinel/tag bytes. It excludes the outer four-byte GET2 record-length prefix and transfer end marker. Native integers inside it are little-endian; `filetime` is the same original 64-bit value displayed canonically, without the precision lost by the derived millisecond field. Byte strings are lowercase unprefixed hex and never clipped within an included event. Ill-formed UTF-16 string contents use replacement characters in `data`, with `data_utf16_valid:false`; original code units remain exact in `record_hex`.

Valid untagged records end after their zero-terminated UTF-16 strings and need no sentinel. String bytes resembling `STCK` are not mistaken for a tag. `0xffff` is interpreted as the tag sentinel only at a string boundary and must precede at least one complete tag header. Every tag has a little-endian four-byte ID, four-byte byte length and exactly that many payload bytes, with no invented alignment/padding. Odd payload lengths and well-framed unknown IDs are preserved. `tags` is empty for untagged records; `name` is `STCK` for ID `0x5354434b` and null for unknown IDs. No native stack addresses are filtered or symbolized: raw tag bytes may include kernel addresses. Broken framing stops the capture with a failure and partial prior events, not a claim that malformed bytes were successfully decoded.

Type decoding follows only the official pinned `api_flags.h`, never text guesses. `type_id` is `type & 0xff`: IDs `0x01` through `0x12` map in order to `MONITOR_SYSCALL`, `MONITOR_PIPE`, `MONITOR_IPC`, `MONITOR_WINCLASS`, `MONITOR_DRIVE`, `MONITOR_COMCLASS`, `MONITOR_RTCLASS`, `MONITOR_IGNORE`, `MONITOR_IMAGE`, `MONITOR_FILE`, `MONITOR_KEY`, `MONITOR_OTHER`, `MONITOR_NETFW`, `MONITOR_SCM`, `MONITOR_APICALL`, `MONITOR_RPC`, `MONITOR_DNS`, `MONITOR_HOOK`; unknown IDs have a null name. `disposition` preserves `type & 0x000f0000`, and `result` preserves `type & 0x00f00000`. `flags` lists only set known bits: `MONITOR_OPEN=0x00010000`, `MONITOR_DENY=0x00020000`, `MONITOR_ALLOWED=0x00100000`, `MONITOR_DENIDED=0x00200000` (the official spelling), `MONITOR_SUCCESS=0x00400000`, `MONITOR_FAILURE=0x00800000`, `MONITOR_TRACE=0x40000000`, `MONITOR_USER=0x80000000`. Multiple flags remain separate, not interpreted as a synthesized success/failure. `unknown_flags` retains every bit outside those named flags and the low-byte type mask, including reserved/unused bits. Raw numeric `type` is authoritative.

Only records whose still-live same-handle creation time is no later than the record FILETIME and whose PID resolves through `SbieApi_QueryProcess` to the selected box/current Windows session are returned. Membership is bracketed by same-handle live/creation checks. Exited, inaccessible and unattributable processes are discarded rather than guessed. Exact included record bytes are not evidence of full-session or lossless capture.

Capture uses only bulk `API_MONITOR_GET2` (`0x12340048`), with a 1 MiB transfer buffer, strict record bounds, at most 128 strings per event, at most 4,096 events, a 2 MiB JSON output cap, 65,536 inspected records and 64 bulk transfers. The event budget reserves 4 KiB within that cap for the response envelope and diagnostics; raw record/tag hex and decoded fields all count toward it. An event that does not fit is omitted whole, never hex-clipped, and sets `truncated:true`. A reached limit sets `truncated:true`; the bridge then waits out the capture window without consuming more records. It returns results only when the window ends. After capture starts, driver errors, malformed framing, cancellation and cleanup errors return failure with any partial events and `truncated:true`. A refusal before capture does not claim that records were captured or truncated. The driver can also drop records without exposing a reliable loss count; `truncated:false` does not guarantee completeness. No capture starts automatically.

Monitoring is shared across the Windows session, not scoped to a box. GET2 destructively pops records, including records discarded by this bridge for other boxes. Another viewer can consume records or race the capture. Installed 1.18.8 has no atomic acquisition, ownership token or owner-scoped release. The exclusive acknowledgement is a caller promise, not an OS-enforced reservation: no other viewer may start or stop monitoring during capture. Stopping frees the shared buffer and discards remaining records, including other-box records. Cleanup runs only after this invocation enabled monitoring, with disable readback and explicit cleanup errors. RAII handles ordinary unwinding; console cancellation requests cleanup. Forced process termination, a crash or Windows shutdown can still leave monitoring enabled. Do not automatically retry a failed capture or disable a monitor whose ownership is uncertain.

The legacy `API_MONITOR_GET_EX` is never called. Its bounds fix is newer than the supported installation.

```json
{"op":"settings","box":"DefaultBox","values":{"FileTrace":"AD","KeyTrace":"D","ApiTrace":"y","DebugTrace":null}}
```

Only explicitly supplied per-box keys are touched. The complete request is validated before the first write:

- `FileTrace`, `KeyTrace`, `PipeTrace`, `IpcTrace`: exactly `"AD"`, `"D"`, `"A"`, or JSON `null` to remove the per-box override.
- `ApiTrace`, `DebugTrace`, `ErrorTrace`, `HookTrace`: exactly `"y"`, or JSON `null` for explicit removal.

Removing a per-box override does not guarantee effective tracing is off: a global or template value may be inherited.

One through eight keys are required. Global settings, templates, isolation rules and all other keys/values are rejected. Writes use the installed `SbieIni.exe set` with a separate argument vector, null stdio, a trusted working directory and a 10-second process deadline. Children are reaped, including after timeout termination. SbieIni's exit status alone is insufficient: every attempted write is read back using the driver API with global fallback, template inheritance and expansion disabled, including checking for unexpected additional values and confirming removal.

The response contains a result for each requested key with `attempted`, `requested`, `ok`, `readback` and `error`. Writes are sequential in key order, not transactional. A failed write or readback stops later writes. Earlier successful changes remain; there is no retry or rollback that could overwrite a concurrent editor's changes. If a write times out, its final effect is uncertain and the response says so. Existing sandbox processes may need restarting before trace settings take effect; the bridge does not restart them.

## ABI references

Bindings and record layout were checked against official tag `v1.18.8`:

- [Driver arguments and operation IDs](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/core/drv/api_defs.h)
- [Official bulk monitor reader](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/SandboxiePlus/QSbieAPI/SbieAPI.cpp#L2982-L3172)
- [Monitor state, ownership limitations and GET2 implementation](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/core/drv/session.c#L666-L757)
- [DLL API signatures](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/core/dll/sbieapi.h)
- [Direct sandbox launch signature](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/core/dll/sbiedll.h#L127-L129)
- [Official type, disposition, result and configuration flags](https://raw.githubusercontent.com/sandboxie-plus/Sandboxie/v1.18.8/Sandboxie/core/drv/api_flags.h)
- [Record writer and sentinel/tag layout](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/core/drv/session.c#L595-L649)
- [QueryProcess implementation and fixed output lengths](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/core/dll/sbieapi.c#L525-L634)
- [Box-name buffer size](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/common/defines.h#L54)
- [Installed-version ABI constant](https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/common/my_version.h#L39)

The DLL is loaded only by its fixed absolute installation path, using DLL-directory and System32-only dependency lookup. Exports are resolved dynamically and missing exports fail closed. Win32 declarations and structures use the installed pinned `windows-sys =0.61.2` bindings for Toolhelp, Debug, Memory, Threading, RemoteDesktop and SystemInformation; no hand-guessed process-array or memory-information ABI is used. The lockfile does not need changes for these feature additions.

A Windows build and owned-process inspection/approved write were exercised locally before packaging. Nonempty trace capture and other-version, WOW64 and race behavior remain unverified. No new build, tests or bridge execution were performed for this packaging step.
