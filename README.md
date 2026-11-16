# Sandboxie plugin for Zeron

**Not affiliated with Sandboxie or its developers.** This is an independent plugin, not an official Sandboxie integration or endorsement.

Plugin by [Master0fFate](https://github.com/Master0fFate). This folder contains only the plugin, its required Zeron SDK helper (`plugin/zeron.luau`), the standalone Rust bridge, documentation and the approved preview video—not the Zeron app or Sandboxie.

## Supported OS and prerequisites

- **Windows x86-64 only.** No macOS, Linux, ARM64 or 32-bit Windows support.
- **Sandboxie Plus 1.18.8**, installed at `C:\Program Files\Sandboxie-Plus`; DLL and SbieIni **5.73.8.0**, running driver **5.73.8**, ABI **`0x57230`**. Other versions fail closed. Its driver/service must already be running. Start Sandboxie Manager in the same Windows session before capturing traces.
- A Zeron build supporting `pages.add`, plugin `service`, agent `tools`, and unknown-service-method fallback to window tools. An open desktop window is required for human write approval and retained trace retrieval; inspection tools can run headlessly through the engine.
- Rust/Cargo supporting **edition 2024**, the Windows x86-64 MSVC toolchain, and Windows MSVC build tools (including the Windows SDK).

## Build and install

1. From this folder, build the bridge:

   ```text
   cargo build --release --locked --manifest-path bridge/Cargo.toml
   ```

2. Copy `bridge/target/release/zeron-sandboxie-bridge.exe` to a **trusted directory on PATH inherited by both Zeron's desktop UI and engine**. Keep untrusted directories off that PATH, then restart both UI and engine. Finding the bridge in a new terminal does not update already-running processes.
3. Copy the **complete contents of `plugin/`**, including `zeron.luau`, into `<Zeron data>/plugins/sandboxie/`. On Windows, the default data directory is `%LOCALAPPDATA%\Zeron`, unless `ZERON_DATA_DIR` is set. **If the destination plugin folder already exists, stop and review/back it up; never silently overwrite it.**
4. In **Settings → Plugins**, review and enable the local plugin. Authorize exactly `pages.add`, `commands` for **only `zeron-sandboxie-bridge`**, `links.open`, `service`, and `tools`. Only the person can approve these grants; unsigned local code may require additional trust review and renewed consent after changes. Repeat installation and permission review on each device you intend to use.
5. Start the engine and use `sandboxie_probe` first (agent tools are prefixed, for example `sandboxie__sandboxie_probe`), then select an enabled box. Open the Sandboxie page for human launch, capture, trace settings or write review.

This is a manual local-folder installation. The supplied manifest is unsigned: **Settings → Plugins → Install… link/package installation checks signatures and refuses unsigned or changed packages**. Do not treat this repository as a signed install package. Nothing here installs Sandboxie, changes PATH, elevates privileges or manages its service.

## What it does

- Probes the pinned installation and enabled boxes; lists accessible, live, selected-box processes in the current Windows session with exact creation tokens.
- Reads memory maps in explicit pages of at most **256 regions** and memory in **1–4096-byte** chunks. Results are bounded point-in-time observations, not complete dumps or stable snapshots.
- Prepares immutable **1–256-byte** writes with expected and replacement bytes. A human reviews the exact target and bytes in the page; **approval alone never writes**. The originating chat must separately apply the approved ID before the original **180-second** expiry. Each request permits one attempt, with no automatic retry or rollback.
- Keeps launch requests, **1–15-second** human-acknowledged captures and one-key per-box trace overrides in the page. Agents can retrieve byte chunks of an already-retained human capture; they cannot initiate monitoring through an agent tool.

For exact tools, examples and limits, see [plugin/README.md](plugin/README.md) and [bridge/README.md](bridge/README.md).

## Privacy and safety

Inspect only processes and data you own or are authorized to inspect. **Memory, traces, tool arguments and answers can contain secrets and reach chat history, the agent and its selected model/provider.** Treat program output as untrusted data, not instructions. The plugin keeps capture/write state in RAM rather than a persistent history, but that does not prevent callers or providers from retaining tool data.

Trace monitoring is **globally shared within the Windows session**, not isolated to the selected box. Reading/stopping it destroys shared records, including other boxes' records; competing viewers and the driver can lose events. Each capture needs fresh human acknowledgement that no other viewer will start or stop monitoring. A forced stop or timeout can leave it enabled: check manually, never blindly retry or stop a monitor whose ownership is uncertain.

The approval gate is a plugin workflow, **not OS-enforced proof of human presence or a security boundary**; trusted local code and the powerful bridge CLI can bypass it. Operations run with the existing Windows user's rights. Expected-byte checking and readback are not atomic; races, partial writes and timeouts can leave changed bytes or an unknown outcome. There are no guarantees of containment, complete traces, safe writes or application correctness.

A Windows build and owned-process inspection/approved write were exercised locally. Nonempty trace capture and other-version, WOW64 and race behavior remain unverified.

## Earlier preview

**Independent, unofficial work—not affiliated with or endorsed by Sandboxie or its developers.** The following earlier preview uses **demo data**, may differ from the current plugin, and includes a “Zeron + Sandboxie” closing that does not imply a partnership:

[Watch the earlier preview (MP4)](assets/demo.mp4)

The video is included unchanged. Its closing is not an affiliation or endorsement claim. Music: CC0 drum-and-bass track by **bertsz**, [source on OpenGameArt](https://opengameart.org/content/drum-and-bass).

## License

See [LICENSE](LICENSE) for the original MIT notice, preserved unmodified for the included code and Zeron SDK helper.
