# GateJumper

Injection-based bypass and plugin loader for Unity games protected by
commercial anti-cheat packers, running on Windows, Wine, and Proton.

No game files are touched or replaced — everything happens at runtime through
standard process injection.

## How It Works

Commercial anti-cheat packers replace the game executable's entry point with
an unpacker stub that decompresses game code into memory, fixes the import
table, starts integrity watchdogs, and then hands off to the real Unity entry
point. GateJumper intercepts the launch sequence before any of that happens,
loading the Unity engine directly while leaving the packer dormant in memory.

CrackProof replaces the real Unity executable with an unpacker stub (the
original is kept as `<name>.exe._`). Under Wine/Proton, this stub faults during
unpacking. GateJumper bypasses this by taking over execution before the stub runs:

1. The injector spawns the game executable suspended and injects
   `gatejumper.dll` via APC.
2. `DllMain` loads any plugins from `plugins/` early.
3. If driver suppression is enabled (`GATEJUMPER_SUPPRESS_DRIVERS=1`), a deferred
   thread installs runtime hooks intercepting driver loading and probe calls.
4. `DllMain` patches the packer's entry point stub with a 14-byte absolute JMP
   redirecting to `launch_unity()`.
5. When the OS resumes the process, execution goes directly to
   `launch_unity()`. The packer stub never runs; its watchdog threads never
   start.
6. `launch_unity()` loads `UnityPlayer.dll`, resolves `UnityMain`, strips
   `argv[0]` from the command line, and calls `UnityMain(hInstance, NULL,
   cmdline, 10)`.

Because the stub is never allowed to run, it cannot fault under Wine/Proton.

## Components

| Binary | Purpose |
|---|---|
| `injector.exe` | Launch wrapper. Spawns the target process suspended and injects `gatejumper.dll` via APC. Rename to `start.exe` for deployment. |
| `gatejumper.dll` | Core payload. Detects the packing layout, loads plugins, and performs the appropriate bypass. |
| `dmmhook.dll` | DMM launcher hook. Injected into DMM Game Player or DMM Fast Launcher; intercepts process-launch APIs (`CreateProcessW/A`, `ShellExecuteW/A/ExW`, `WinExec`), follows the launcher's own runtime child (PyInstaller one-file) and arms command interpreters that carry a configured game, then injects `gatejumper.dll` — resolved from its own directory — when the game starts. |

## Building

Targets `x86_64-pc-windows-msvc`. Binaries run on both Windows and Wine/Proton.

**On Windows:**
```sh
cargo build --release
```

**On Linux (cross-compilation via [cargo-xwin](https://github.com/rust-cross/cargo-xwin)):**
```sh
cargo xbuild
```

Outputs land at `target/x86_64-pc-windows-msvc/release/`.

Unit tests (shellcode layout assertions, Wine/prefix path resolution, carrier
matching, command-line splitting):

```sh
cargo test --target x86_64-pc-windows-msvc
```

## Usage

Installation and launch setup (Steam, non-Steam, DMM Game Player, DMM Fast
Launcher), plugin loading, configuration, target resolution and logging are
documented in **[USAGE.md](USAGE.md)**.

The short version: put `start.exe` + `gatejumper.dll` in the game's root
directory (or in a dedicated folder of their own for DMM launchers, adding
`dmmhook.dll`), point the launch at `start.exe`, and add `plugins/` next to
the binaries to load mods.

## Logs

`gatejumper.log` next to the loaded binaries — see
[USAGE.md § Logs](USAGE.md#logs).

## Acknowledgements

- **[FunnyHoney](https://gitlab.com/LeadRDRK/FunnyHoney)** (LeadRDRK) — The foundational proof-of-concept that demonstrated bypassing commercial anti-cheat stubs, inspiring GateJumper's non-destructive runtime injection design.
- **[Cellar](https://github.com/Hachimi-Hachimi/Cellar)** — Early exploration of Windows DLL redirection and environment isolation under Wine/Proton.
- **[MinHook](https://github.com/TsudaKageyu/minhook)** — Minimalistic x86/x64 API hooking library for Windows.