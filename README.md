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
| `dmmhook.dll` | DMM Game Player hook. Injected into the launcher; intercepts all process-launch APIs (`CreateProcessW/A`, `ShellExecuteW/A/ExW`, `WinExec`), then injects `gatejumper.dll` — resolved from its own directory — into the game when the launcher starts it. |

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

## Installation

### Steam (Windows & Linux)

1. Copy `injector.exe` (rename it `start.exe`) and `gatejumper.dll` into the
   game's root directory, next to `UnityPlayer.dll`.
2. Optionally create a `plugins/` folder and place `.dll` plugins inside it.
3. Set the Steam Launch Options:

   **Windows:**
   ```
   "C:\path\to\game\start.exe" %command%
   ```

   **Linux / Proton** — replace `Game.exe` with the actual executable name:
   ```sh
   eval $(echo "%command%" | sed 's/Game\.exe/start\.exe/')
   ```

4. Launch normally via Steam.

### Non-Steam (Windows & Linux/Wine)

Place `start.exe` and `gatejumper.dll` in the game root, then use any of the
following:

**Config file (`gatejumper.ini` beside `start.exe`):**
```ini
# Direct game target — relative (resolved against this file's directory)
# or absolute:
target = Game.exe

# Or, to route through DMM Game Player:
# dmm = true
```

**No configuration:** just run `start.exe` from the game's root directory — it
finds the game executable itself (see [Target Resolution](#target-resolution)).

### DMM Game Player

> **Important:** DMM-managed games require authentication tokens that DMM Game
> Player passes to the game at launch. Launching the game executable directly
> from its folder **will fail** — the game contacts DMM servers and finds no
> valid session. You must route the launch through DMM Game Player.

> **DMM updates wipe DMM Game Player's own directory and the game's directory,
> reinstalling both from scratch.** Nothing GateJumper-related may live inside
> either tree. Instead, keep the entire setup in a folder of its own anywhere
> else on the system: GateJumper injects both the launcher hook and the game
> payload from that folder by absolute path, so neither managed directory is
> ever touched and updates cannot break the installation.

1. Create a GateJumper folder outside both DMM Game Player's directory and the
   game's directory (e.g. `C:\GateJumper` on Windows, or `/media/…/GateJumper`
   on Linux) and copy `injector.exe` (rename to `start.exe`), `dmmhook.dll`,
   `gatejumper.dll`, and optionally a `plugins/` folder into it. Both DLLs must
   sit next to `start.exe` — the injector refuses to run without them.
2. Create a `gatejumper.ini` beside `start.exe` that routes the launch through
   DMM Game Player (this also makes double-click launching work) and lists the
   games DMM-Hook should arm. The file uses one section per game, keyed by the
   game executable's file name:

   ```ini
   [main]
   dmm = true
   # Optional: point at an explicit DMM Game Player install directory instead
   # of auto-detecting the standard locations:
   # target = C:\Program Files\DMMGamePlayer

   [ExampleGame.exe]
   dir = C:\Games\ExampleGame
   plugins = true             # explicit: load plugins/ for this game

   [AnotherGame.exe]
   dir = C:\Games\AnotherGame
   plugins = false            # explicit: skip plugin loading for this game
   ```

   `[main]` is read by the injector: `dmm = true` routes the launch through
   DMM Game Player, and the optional `target` names the launcher's install
   directory (a bare `DMMGamePlayer.exe` path also works). Each `[<exe>]`
   section is read by DMM-Hook: when DMM Game Player spawns that executable,
   `gatejumper.dll` is injected with the listed `plugins` override (`true`/`false`;
   omit to use the default — load if a `plugins/` directory exists beside the payload). The
   section's `dir`, when present, must match where the game
   actually launched from.

   Games that match no section are launched completely normally — no
   injection, no bypass, no mod loading — with one exception: a game whose own
   directory contains a `gatejumper.dll` (a standalone install that DMM now
   launches) counts as implicitly armed, and the payload is injected.

   On Linux/Wine the same ini works — `dir` accepts a Windows path
   (`C:\...`, `Z:\...`), a Linux path reachable through the prefix's `Z:`
   drive, or a relative path. See [Target Resolution](#target-resolution).

3. Launch `start.exe` (double-click, or `wine start.exe` on Linux). The
   injector spawns DMM Game Player suspended and injects `dmmhook.dll` from
   the GateJumper folder.
4. Click Play in DMM. The hook intercepts the authenticated game launch,
   matches the spawned executable against the configuration, and injects
   `gatejumper.dll` — again resolved from the GateJumper folder, never from
   the game's directory — so the bypass is applied and plugins load from
   `<GateJumper folder>/plugins`.

   A `gatejumper.ini` sitting inside a game's own directory is treated as that
   game's individual config:

   ```ini
   # <game directory>/gatejumper.ini
   plugins = false
   ```

   This lets per-game settings survive independently of the GateJumper
   folder. DMM update cycles wipe the game directory (nuking this file too), at
   which point DMM-Hook falls back to the `[<exe>]` section of the config in
   the GateJumper folder.

Installing the files into the game's root folder instead still works, but DMM
update cycles delete them; the dedicated folder above survives untouched.

## Plugin Loading

Place `.dll` plugin files in a `plugins/` folder next to the GateJumper
binaries — the game root in standalone/Steam installs, or the dedicated
GateJumper folder in the [DMM Game Player](#dmm-game-player) deployment.
GateJumper scans this directory during `DllMain` and loads each DLL via
`LoadLibraryW` before the bypass fires, ensuring plugins are active before
Unity starts.

Optionally restrict loading to specific DLLs with `GATEJUMPER_PLUGIN_ALLOWLIST`
(see [Environment Variables](#environment-variables)).

## Configuration

### Target Resolution

The executable the injector spawns is chosen from the first match of:

1. `gatejumper.ini` — `[main]`: `target = <path>` or `dmm = true`.
2. The first `.exe` argument on the command line (the Steam `%command%`
   passthrough).
3. A scan of `start.exe`'s own directory (skipping itself, crash handlers,
   and uninstallers).

A `[main]` `target` naming a *directory* is treated as the DMM Game Player
install folder and `DMMGamePlayer.exe` is appended; naming an executable uses
it directly.

`target` values may be any of:

- a **relative path** — resolved against the ini's directory, so `Game.exe` or
  `./Game.exe` both mean the game root that holds `start.exe`. Works under every
  prefix and drive mapping, so it is the recommended form.
- a **Windows path** — used as-is, e.g. `D:\games\Game.exe` or `Z:\media\...`.
  Any drive letter the prefix actually provides works, including non-`Z:`
  mappings made by a prefix manager.
- a **Linux path** — e.g. `/media/extra/.../Game.exe` — translated through the
  prefix's `Z:` drive (Wine mounts `/` as `Z:` by default) and only accepted if
  the file is reachable there. Prefixes that remap or remove `Z:` hide their
  drive mappings from the process, so in that case use a relative or Windows
  path instead (you can get the latter once with `winepath -w`).

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GATEJUMPER_LOAD_PLUGINS` | *(auto: on if `plugins/` exists)* | `1` / `true` to force-enable, `0` / `false` to disable plugin loading. |
| `GATEJUMPER_PLUGIN_ALLOWLIST` | *(unset — load all)* | Comma-separated list of plugin filenames to restrict loading to. |
| `GATEJUMPER_PLUGINS_DIR` | `<payload folder>/plugins` (the game root in standalone/Steam installs, the GateJumper folder in the DMM flow) | Override the plugin directory path. |
| `GATEJUMPER_SUPPRESS_DRIVERS` | `0` | Set to `1` to intercept `NtLoadDriver` / `NtCreateFile` for known anti-cheat driver names. |
| `GATEJUMPER_STRICT_PROBES` | `1` | Set to `0` to narrow the driver suppression filter to driver filenames only. |

## Logs

`gatejumper.log` is written next to the loaded binaries — the game root in
standalone/Steam installs, the dedicated GateJumper folder in the
[DMM Game Player](#dmm-game-player) deployment. Each launch appends to this
file with a timestamped separator (`─── YYYY-MM-DD HH:MM:SS ───`), so the full
history of all sessions is preserved. The injector writes its lines before the
payload loads, making it the first place to check if something goes wrong.
Deferred-runtime activity is logged separately to `gatejumper-deferred.log` in
the same folder.