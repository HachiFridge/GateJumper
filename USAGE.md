# GateJumper Usage

Installation, launch setup, plugins, configuration and logging. Project
overview and build instructions: [README.md](README.md).

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

### DMM Fast Launcher

> **Windows only.** [DMM Fast Launcher](https://github.com/fa0311/DMMGamePlayerFastLauncher) is a Windows application with no Linux/Wine release.

[DMM Fast Launcher](https://github.com/fa0311/DMMGamePlayerFastLauncher)
(`DMMGamePlayerFastLauncher.exe`) launches games itself rather than through
DMM Game Player, and goes through `cmd.exe` while doing so — one process
further away than the official launcher. DMM-Hook follows the launcher's own
runtime child (it re-executes itself), arms that command interpreter — but
only when its command line names a configured `[<exe>]` game, so unrelated
launches stay untouched — and injects `gatejumper.dll` when the game itself
starts.

The Fast Launcher GUI is configuration-only and has no launch button; games
are launched by **shortcut id**. Two things must exist before GateJumper can
route a launch:

1. **A saved game shortcut inside Fast Launcher.** Create one in the Shortcut
   tab and hit *Save Settings Only* (or any of the create-shortcut buttons).
   This writes `data/shortcut/<id>.json` — that `<id>` is the shortcut's file
   name without `.json`, and it is what names the game on Fast Launcher's
   command line.
2. **An armed game section in `gatejumper.ini`** beside `start.exe`, keyed by
   the game executable's file name:

   ```ini
   [ExampleGame.exe]
   dir = C:\Games\ExampleGame    # must match where the game actually lives
   plugins = true                 # load plugins/ for this game
   ```

   No `[main]` entry is needed — the Fast Launcher is named on the command
   line, and an explicit argument beats any `[main] target` anyway.

Then wrap this command in a desktop shortcut — Target: `start.exe`,
Arguments: the Fast Launcher exe (quoted) followed by the shortcut id:

```
"C:\Users\<you>\AppData\Roaming\DMMGamePlayerFastLauncher\DMMGamePlayerFastLauncher.exe" <shortcut-id>
```

The default install location is `C:\Users\<you>\AppData\Roaming\DMMGamePlayerFastLauncher`. "Start in" can be anything — the target is spawned with its own directory as the
working directory. Tick **Run as administrator** on the shortcut: for DMM
games flagged as admin-required, an unelevated launcher hands the launch to
UAC, which creates the game outside the hook chain.

Fast Launcher's own *UAC auto-elevation* (Task Scheduler) shortcuts are
passed through untouched: their elevated launcher process is created by the
system, outside any armed chain — use the routed shortcut above instead.

## Plugin Loading

Place `.dll` plugin files in a `plugins/` folder next to the GateJumper
binaries — the game root in standalone/Steam installs, or the dedicated
GateJumper folder in the [DMM Game Player](#dmm-game-player) deployment.
GateJumper scans this directory during `DllMain` and loads each DLL via
`LoadLibraryW`, ensuring plugins are active before Unity starts.

Optionally restrict loading to specific DLLs with `GATEJUMPER_PLUGIN_ALLOWLIST`
(see [Environment Variables](#environment-variables)).

## Configuration

### Target Resolution

#### What gets spawned

The executable the injector spawns is chosen from the first match of:

1. The first `.exe` argument on the command line — an explicit choice always
   beats the ini default (the Steam `%command%` passthrough, or e.g.
   `start.exe DMMGamePlayerFastLauncher.exe <shortcut-id>`).
2. `gatejumper.ini` — `[main]`: `target = <path>` or `dmm = true`.
3. A scan of `start.exe`'s own directory (skipping itself, crash handlers,
   and uninstallers).

A `[main]` `target` naming a *directory* is treated as the DMM Game Player
install folder and `DMMGamePlayer.exe` is appended; naming an executable uses
it directly.

The target is always spawned with **its own directory as the working directory**
(matching a double-click launch), so CWD-relative resources — e.g. DMM Fast
Launcher's `assets` folder — resolve correctly no matter where `start.exe`
was started from.

#### Path forms accepted by `target =`

**Relative path** *(recommended)* — resolved against the ini's own directory.
`Game.exe` or `./Game.exe` both mean the file in the same folder as `start.exe`.
Works identically on Windows and under every Wine prefix layout, so it is the
safest choice whenever the ini sits beside the game.

**Windows absolute path** — used as-is. Any drive letter the prefix provides
works: `D:\games\Game.exe`, `Z:\media\...\Game.exe`, `C:\Program Files\...`.
Non-`Z:` drive letters created by a prefix manager (Bottles, Lutris, Faugus,
Proton) are all accepted as long as the file is actually there.

**Linux absolute path** *(Wine/Proton only)* — a path starting with `/` is
translated in two steps:

1. **`Z:` drive** — Wine mounts the Linux root `/` as `Z:\` by default, so
   `/home/user/games/Game.exe` becomes `Z:\home\user\games\Game.exe`.
   GateJumper tries this first and uses it if the file exists there.
2. **`drive_<letter>` segment** — prefix managers (Steam/Proton, Bottles,
   Lutris, Faugus, plain Wine) store additional drives as `drive_c`, `drive_d`,
   … directories inside the prefix folder. If the path contains such a segment,
   e.g. `/home/user/.steam/steam/compatdata/123/pfx/drive_c/games/Game.exe`,
   GateJumper extracts the drive letter and tail to produce `C:\games\Game.exe`
   and tries that next.

Both candidates are verified to exist before being accepted. If neither is
reachable (e.g. a prefix that remaps or removes `Z:`, or a path that does not
pass through a `drive_<letter>` segment), GateJumper logs a specific error and
exits rather than guessing. In that case, use a relative or Windows path
instead — you can get the Windows form once with `winepath -w /your/linux/path`.

#### `dir =` matching in the DMM flow

In the DMM Game Player and DMM Fast Launcher flows, `dmmhook.dll` checks the
`dir =` value in each `[<exe>]` section against the directory the game actually
spawned from. This comparison is path-form-agnostic: both sides are normalised
to lowercase with forward slashes folded to backslashes, and each is expanded
into its Wine alias set before comparing — so a config written with a Windows
path (`C:\Games\ExampleGame`) will correctly match a process whose image path
reports a `Z:\`-prefixed or `drive_c`-style form of the same location, and
vice versa. You can write `dir =` in whichever form is most natural; the
comparison handles the rest.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GATEJUMPER_LOAD_PLUGINS` | *(auto: on if `plugins/` exists)* | `1` / `true` to force-enable, `0` / `false` to disable plugin loading. |
| `GATEJUMPER_PLUGIN_ALLOWLIST` | *(unset — load all)* | Comma-separated list of plugin filenames to restrict loading to. |
| `GATEJUMPER_PLUGINS_DIR` | `<payload folder>/plugins` | Override the plugin directory path. Defaults to a `plugins/` folder beside the payload DLL — the game root in standalone/Steam installs, the GateJumper folder in the DMM flow. |
| `GATEJUMPER_SUPPRESS_DRIVERS` | `0` | Set to `1` to intercept `NtLoadDriver` / `NtCreateFile` for known anti-cheat driver names. |
| `GATEJUMPER_STRICT_PROBES` | `1` | Set to `0` to narrow the driver suppression filter to driver filenames only. |

## Logs

`gatejumper.log` is written next to the loaded binaries — the game root in
standalone/Steam installs, the dedicated GateJumper folder in the
[DMM Game Player](#dmm-game-player) deployment. Each launch appends to this
file with a timestamped separator (`─── YYYY-MM-DD HH:MM:SS ───`). Up to 5 launch
entries are preserved; launching a 6th time completely nukes the logs (both
`gatejumper.log` and `gatejumper-deferred.log`) and begins logging fresh from scratch.
The injector writes its lines before the payload loads, making it the first place to check
if something goes wrong. Deferred-runtime activity is logged separately to
`gatejumper-deferred.log` in the same folder.