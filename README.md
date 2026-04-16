# GateJumper

Advanced anti-cheat bypass for Unity games on Linux (Wine/Proton) via Entry Point Hijacking.

## Architecture

GateJumper utilizes a **Direct Entry Point Hijack** model designed to circumvent anti-cheat packers (like CrackProof) before they execute a single instruction:

1.  **Suspended Launch:** The `injector.exe` launches the target game process in a suspended state.
2.  **Late-Stage Injection:** It uses Asynchronous Procedure Calls (APC) to inject `gatejumper.dll` into the process memory using absolute path resolution.
3.  **OEP Hijacking:** Once injected, `gatejumper.dll` calculates the game's original AddressOfEntryPoint (OEP) and patches the first 14 bytes with an absolute jump to its own engine launcher.
4.  **Engine Direct-Boot:** When the process is resumed, execution immediately jumps to GateJumper. We then manually load `UnityPlayer.dll` and call `UnityMain`, booting the game engine directly while leaving the anti-cheat packer completely inactive.

## Features

- **Dynamic Detection:** Injector automatically finds the game executable in its directory.
- **Zero Dependencies:** Statically linked CRT; no VC++ redistributable required.
- **Proton Optimized:** Uses absolute path resolution to handle Wine's working directory quirks.
- **Passive Stealth:** By never letting the anti-cheat run, we avoid detection loops and watchdog crashes.

## Building

Requires [cargo-xwin](https://github.com/rust-cross/cargo-xwin).

```bash
cargo build-win-rel
```

## Installation

1.  Copy `injector.exe` and `gatejumper.dll` (from `target/x86_64-pc-windows-msvc/release/`) into the game root.
2.  Ensure no existing proxy DLLs (like `version.dll`) are in the game folder.

## Steam Launch Options

Add the following to your Game Properties > General > Launch Options (replace `GameExecutable.exe` with your game's original EXE name):

```bash
eval $(echo "%command%" | sed 's/GameExecutable\.exe/injector\.exe/')
```
