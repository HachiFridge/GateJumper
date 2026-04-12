# GateJumper (Generic Template)

A clean, injection-based CrackProof bypass for running Unity Engine games flawlessly on Linux running under Wine/Proton.

## How it Works

CrackProof enforces an intense ring-0 integrity-verification sequence across core system APIs (`ntdll` / `kernelbase` etc.) and initiates an RPC health-check heartbeat which intentionally fails inside a Wine/Proton environment, cascading into a forceful engine crash via dummy `EXCEPTION_ACCESS_VIOLATION` null-pointer jumps.

Rather than trying to neuter the RPC checks, modify API imports dynamically, or rebuild the entire standalone Unity executable layout (which runs the risk of hard-bricking during major engine refactors), GateJumper acts as an **Origin Entry-Point Hijacker**.

1. `injector.exe` kicks off the unmodified/original game executable completely suspended.
2. The injector explicitly queues an APC thread forcing the game to natively load `gatejumper.dll` before unpacking starts.
3. `gatejumper.dll` strips memory locks and hard-patches the Original Entry Point of the `.bind` sector with an absolute `jmp`.
4. Execution breaks out of the `.bind` sector and lands securely in `gatejumper.dll` unhooked space.
5. The payload in `gatejumper.dll` bypasses CrackProof, completely ignores the protective `.bind` routine, fetches the `UnityMain` pipeline organically via `LoadLibrary`, and starts the generic engine sequence unmodified.

## Building & Deploying

1. Open `injector/src/main.rs`.
2. Locate the static `REAL_GAME_EXE` definition and modify it to match your target game's binary name:
   `const REAL_GAME_EXE: &str = "<INSERT_GAME_EXECUTABLE_HERE.exe>";`

```bash
# Build the injector (the starter binary)
cargo xwin build --manifest-path=injector/Cargo.toml --target x86_64-pc-windows-msvc --release

# Build the hijack payload (the bypassed code logic)
cargo xwin build --manifest-path=gatejumper-payload/Cargo.toml --target x86_64-pc-windows-msvc --release
```

## Setup Rules
**Do not rename your actual game executable.** Keep it as is to allow tools and the Unity API to discover its folders securely.

- Copy `injector.exe` and `gatejumper.dll` directly to the game's root directory.

- **For Steam Users (Proton):**
  - In Steam, right-click the game -> Properties -> Launch Options.
  - Because Proton wraps `%command%` in a Linux environment, we must use a Linux bash string rewrite to safely swap the final Windows target. Replace `<main_executable_name>` with your game's main executable name.
    ```bash
    eval $(echo "%command%" | sed 's/<main_executable_name>\.exe/injector\.exe/')
    ```

  *(This trick intercepts Steam's boot sequence seamlessly, keeping everything safely contained inside a single Proton wineprefix while executing your `injector.exe` first!)*

- **For Standalone Wine Users:**
  - Run `injector.exe` directly via standard Wine within your wineprefix:
    `wine injector.exe`
  - If using Lutris or a custom launcher, change the game's executable target in the launch configuration to point directly to `injector.exe`. The injector will automatically locate the relevant target executable in the directory.
