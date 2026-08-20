# GateJumper

Injection-based bypass and plugin loader for Unity games protected by commercial anti-cheat packers, running on Windows, Wine, and Proton.

GateJumper intercepts a game's launch sequence before the packer can initialize its watchdog threads, loading the Unity engine directly while leaving the packer completely dormant in memory. No game files are touched or replaced — everything happens at runtime through standard process injection.

## How It Works

Commercial anti-cheat packers replace the game executable's entry point with an unpacker stub that decompresses game code into memory, fixes the import table, starts integrity watchdogs, and then hands off to the real Unity entry point. GateJumper intercepts before any of that happens.

Two packing layouts are detected automatically from the files present in the game directory:

**Full packer layout** (`installer/` directory present):

1. The injector spawns the game executable suspended and injects `gatejumper.dll` via APC.
2. `DllMain` loads plugins early, then patches the packer's entry point stub with a 14-byte absolute JMP redirecting to `launch_unity()`.
3. When the OS resumes the process, execution goes directly to `launch_unity()`. The packer stub never runs; its watchdog threads never start.
4. `launch_unity()` loads `UnityPlayer.dll`, resolves `UnityMain`, strips `argv[0]` from the command line, and calls `UnityMain(hInstance, NULL, cmdline, 10)`.

**Partial packer layout** (`GameAssembly.dll` present on disk, no `installer/` directory):

1. The injector spawns the game executable suspended and injects `gatejumper.dll` via APC.
2. `DllMain` loads plugins early. The original entry point is **not** patched.
3. The packer stub runs normally, decrypting and decompressing code sections into memory via raw file-mapping — bypassing the Win32 loader entirely.
4. After the packer finishes, Unity loads its native plugin DLLs through the normal loader. GateJumper hooks `LoadLibraryExW` and relays relevant loads through `LoadLibraryW` so any plugin that hooked `LoadLibraryW` can observe them and complete initialization.

> **Note on Wine/Proton:** For the partial packer layout, plugins placed in `plugins/` initialize correctly. However, background threads spawned from `DllMain` are not reliably scheduled by Wine/Proton during the packer's CPU-intensive unpacking phase. GateJumper's relay hook runs on the main thread and is not affected.

## Components

| Binary | Purpose |
|---|---|
| `injector.exe` | Launch wrapper. Spawns the target process suspended and injects `gatejumper.dll` via APC. Rename to `start.exe` for deployment. |
| `gatejumper.dll` | Core payload. Detects the packing layout, loads plugins, and performs the appropriate bypass. |
| `dmmhook.dll` | DMM Game Player hook. Injected into the launcher; intercepts `CreateProcessW` / `ShellExecuteExW` to apply the bypass when the launcher starts the game. |

## Building

Targets `x86_64-pc-windows-msvc`. Binaries run on both Windows and Wine/Proton.

**On Windows:**
```sh
cargo build --release
```

**On Linux (cross-compilation via [cargo-xwin](https://github.com/rust-cross/cargo-xwin)):**
```sh
cargo xbuild --release
```

Outputs land at `target/x86_64-pc-windows-msvc/release/`.

## Installation

### Steam (Windows & Linux)

1. Copy `injector.exe` (rename it `start.exe`) and `gatejumper.dll` into the game's root directory, next to `UnityPlayer.dll`.
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

### DMM Game Player

1. Copy `injector.exe`, `dmmhook.dll`, and `gatejumper.dll` into the game's root folder. Files not named `version.dll` are ignored by DMM's integrity check and survive updates.
2. Optionally create a `plugins/` folder for plugins.
3. Create a shortcut targeting the injector pointed at DMM:
   ```
   "C:\path\to\game\injector.exe" "C:\Program Files\DMMGamePlayer\DMMGamePlayer.exe"
   ```
4. Launch DMM via the shortcut. The injector injects `dmmhook.dll` into the launcher. When you click Play, the hook intercepts the game launch and applies the bypass.

### Standalone

1. Copy `start.exe` (injector) and `gatejumper.dll` into the game's root directory.
2. Optionally create a `plugins/` folder.
3. Run `start.exe`. It scans the current directory for the game executable and launches it with the bypass applied.

## Plugin Loading

Place `.dll` plugin files in a `plugins/` folder next to the game executable. GateJumper scans this directory during `DllMain` and loads each DLL via `LoadLibraryW` before the bypass fires, ensuring plugins are active before Unity starts.

Optionally restrict which DLLs are loaded by setting `GATEJUMPER_PLUGIN_ALLOWLIST` to a comma-separated list of filenames. When unset, all DLLs in the directory are loaded.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `GATEJUMPER_PROFILE` | *(auto-detect)* | Override profile detection: `direct-oep`, `partial-crackproof`, or `hooked-runtime`. |
| `GATEJUMPER_LOAD_PLUGINS` | *(auto: on if `plugins/` exists)* | `1` / `true` to force-enable, `0` / `false` to disable plugin loading. |
| `GATEJUMPER_PLUGIN_ALLOWLIST` | *(unset — load all)* | Comma-separated list of plugin filenames to restrict loading to. |
| `GATEJUMPER_PLUGINS_DIR` | `<game root>/plugins` | Override the plugin directory path. |
| `GATEJUMPER_SUPPRESS_DRIVERS` | `0` | Set to `1` to intercept `NtLoadDriver` / `NtCreateFile` for known anti-cheat driver names. |
| `GATEJUMPER_STRICT_PROBES` | `1` | Set to `0` to narrow the driver suppression filter to driver filenames only. |

## Logs

`gatejumper.log` is written to the game root directory on every launch. The injector appends to this file before the payload loads, making it the first place to check if something goes wrong.
