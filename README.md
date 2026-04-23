# GateJumper

Universal stealth anti-cheat bypass and generic plugin loader for Unity games running on Windows, Wine, and Proton.

GateJumper circumvents heavily obfuscated anti-cheat packers (like CrackProof) without triggering detection by intercepting the game's launch sequence and performing a precise Entry Point (OEP) Hijack before the packer can initialize its watchdogs.

## Features

- **Universal Unity Support:** Works flawlessly with any Unity game wrapped in commercial anti-cheat packers.
- **Cross-Platform & Multi-Launcher:** Full support for Native Windows and Linux (Wine/Proton). Integrates seamlessly into Steam direct-launches, DRM launchers (like DMM Game Player), and standalone unmanaged runs.
- **Built-in Mod Loader:** Automatically scans a `plugins` directory and dynamically loads any `.dll` mods at runtime. This circumvents aggressive launcher integrity sweeps that delete standard proxy DLLs.
- **Passive Stealth:** By intercepting execution *before* the anti-cheat unpacks the game, GateJumper boots straight into the Unity engine, leaving the anti-cheat completely dormant in memory.
- **Native OS Integration:** Operates purely in user-mode with zero kernel drivers required. Proxies load natively via standard OS search order rules, eliminating the need for obsolete `.local` folder redirections.

## Building

This project targets Windows (`x86_64-pc-windows-msvc`). All resulting binaries are natively compatible with Windows and Wine/Proton.

**On Windows:**
Simply build the workspace using standard Cargo:
```bash
cargo build --release
```

**On Linux (Cross-Compilation):**
Requires [cargo-xwin](https://github.com/rust-cross/cargo-xwin) to be installed.
```bash
cargo winbuild-rel
```

## Installation Guide

### 1. Steam Games (Windows & Linux)
Many heavily packed Steam games explicitly mitigate local DLL proxying, preventing you from simply renaming the bypass to `version.dll`. To bypass this, we use the `injector.exe` as a launch wrapper.

1. Navigate to your compiled target directory (`target/x86_64-pc-windows-msvc/release/`).
2. Copy **both** `gatejumper.dll` and `injector.exe` into your game's root directory (where `UnityPlayer.dll` is located).
3. *(Optional)* Create a `plugins` folder in the game's root directory and place your `.dll` mods inside.
4. Set your Steam Launch Options (Right-click your game -> Properties -> General -> Launch Options):
   - **For Windows:**
     ```cmd
     "C:\Path\To\Your\Game\injector.exe" %command%
     ```
   - **For Linux (Proton):** Replace `GameExecutable.exe` with your game's actual EXE name:
     ```bash
     eval $(echo "%command%" | sed 's/GameExecutable\.exe/injector\.exe/')
     ```
5. Launch the game normally via Steam. The injector will intercept the launch, spawn the game safely suspended, inject the payload, and hand over execution.

### 2. DMM Game Player Games (Windows & Linux)
The DMM Launcher strictly verifies the game directory and will forcefully delete unrecognized proxy DLLs. To bypass this, we use a two-part hook system that operates identically across Windows and Wine.

1. **The Launcher Hook:** Copy `hook.dll` from your build output and place it into the **DMM Game Player installation folder** (e.g., `C:\Program Files\DMMGamePlayer`), renaming it to **`version.dll`**.
   - **Linux/Wine Users:** You must explicitly configure a Wine DLL override for `version` (Native, Builtin) within your runner (e.g., Bottles, Lutris, or via `WINEDLLOVERRIDES="version=n,b"`) for the DMM prefix.
   - *This quietly intercepts DMM's launch sequence, preserves the required authentication tokens, and stealth-injects our payload.*
2. **The Payload:** Copy `gatejumper.dll` from your build output and place it into the **game's root folder** (e.g., `D:\Games\YourUnityGame`).
   - *Since it is not named `version.dll`, DMM's integrity check completely ignores it.*
3. *(Optional)* Create a `plugins` folder in the game's root directory and place your mods inside.
4. Launch the game normally via the DMM Game Player.

### 3. Standalone / Normal Run (Windows & Linux)
If you are launching the game completely standalone, without any DRM clients or wrappers:

1. Copy **both** `gatejumper.dll` and `injector.exe` into the game's root directory.
2. *(Optional)* Create a `plugins` folder for your mods.
3. Simply execute `injector.exe` (or run it via Wine). It will automatically scan its current directory, locate the game's executable, and launch it safely with the bypass applied.

## How it Works

1. **Interception:**
   - On **Steam/Standalone**, `injector.exe` uses the `CREATE_SUSPENDED` flag to spawn the game process, subsequently queuing an Asynchronous Procedure Call (APC) to force the process to load `gatejumper.dll`.
   - On **DMM**, `hook.dll` intercepts `ShellExecuteW` directly within the launcher, extracts the secure launch tokens, and performs a similar suspended launch and memory injection.
2. **OEP Hijack:** Once injected, GateJumper locates the game's original AddressOfEntryPoint (OEP). Because the anti-cheat has already modified the PE headers to point to its own unpacking stub, GateJumper overwrites the first 14 bytes of the stub with an absolute jump instruction pointing to its own custom engine launcher.
3. **Execution & Handover:** Once the OS resumes the process, execution immediately jumps to GateJumper. It loads any DLLs found in the `plugins` directory, dynamically locates `UnityPlayer.dll`, formats the `GetCommandLineW()` arguments (ensuring DMM tokens align perfectly), and invokes `UnityMain`. The game boots flawlessly while the anti-cheat remains completely inactive in memory.
