# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What FUZIX Is

FUZIX is a Unix-like operating system for 8-bit (and some 16/32-bit) microprocessors. It descends from the UZI family of UZI/UZI180/UZIX forks, extended from V7 toward System III/V with selected POSIX interfaces. The same core kernel and userspace tree is built for **many CPU architectures** (Z80/Z180/eZ80, 6502/65C816, 6800/6803/6303/6809/68HC11, 8080/8085/8086, 68000, ARM, ESP8266/ESP32, MSP430, PDP-11, NS32K, RISC-V and more) and **~130 target machines/platforms**, without forking the codebase per machine.

The design assumption throughout the kernel is a small, banked-memory, MMU-less, uniprocessor machine where block I/O and user-space access do not block/reschedule.

## Build System

Everything is GNU Make driven from the top-level `Makefile`. The build is controlled by a single `TARGET` (a machine, e.g. `rcbus-6502`, `tiny68k`, `rpipico`), which selects the CPU via `Kernel/platform/platform-$(TARGET)/target.mk`.

```sh
make TARGET=rcbus-6502 -j$(nproc)      # build everything for a target
make TARGET=rcbus-6502 kernel          # kernel only
make TARGET=rcbus-6502 libs            # userspace libraries only
make TARGET=rcbus-6502 apps            # applications only
make diskimage TARGET=rcbus-6502       # build bootable filesystem image(s)
make clean TARGET=rcbus-6502           # clean (per-target)
```

- `TARGET` defaults to `zrc` if unset; **always pass `TARGET=` explicitly.**
- The top-level `Makefile` header lists curated example targets with descriptions. The full set lives under `Kernel/platform/platform-*/`.
- `USERCPU` defaults to `CPU` but can differ (kernel CPU vs userspace CPU). Build sub-targets honor it (e.g. `Makefile.$(USERCPU)`).
- `FUZIX_CCOPTS` controls global optimization (default `-O2`).
- The build prepends `/opt/fcc/bin` and `Build/tools/` to `PATH`, and forces `YACC=byacc` (Bison output is too large for these toolchains).
- The top-level `all` target ordering is: `tools stand ltools libs apps kernel`.
- Output images land in `Images/$(TARGET)/`.

### Toolchains (vary by CPU — see `BUILD_REQUIREMENTS.md`)

There is no single compiler. Each CPU family uses a different toolchain, most of which are **external** and must be installed separately:

- **Z80/Z180, 8080/8085, 6800/6803/6303, 6809, 65C816** → Fuzix Compiler Kit + Fuzix Bintools (`EtchedPixels/Fuzix-Compiler-Kit`, `EtchedPixels/Fuzix-Bintools`), installed to `/opt/fcc`. Some Z80 kernels still need the patched SDCC (`EtchedPixels/sdcc280`).
- **6502/65C816** → `cc65`.
- **6809** → gcc 4.6.4 + lwtools (PPA `tormodvolden/m6809`).
- **68000** → a working cross gcc (see `README.68000.md`; distro m68k packages are often broken). CI uses a kernel.org crosstool m68k toolchain via `CROSS_COMPILE=m68k-linux-`.
- **ESP8266/ESP32** → xtensa-lx106 gcc / esp-idf + esptool.
- **ARM (Pico/TM4C)** → arm-none-eabi gcc + newlib (+ Pico SDK).

Common requirements everywhere: Bash, GNU Make, Byacc.

### CI

`.github/workflows/continuous-integration.yml` builds a matrix of representative targets on every push/PR (`appleiie`, `dragon-mooh`, `dragon-nx32`, `esp32`, `esp8266`, `multicomp09`, `rbc-mark4`, `rcbus-6502`, `rcbus-68008`, `rpipico`, `sc108`, `tiny68k`, `armm0-libc`). `fail-fast: false` so all targets build even if one fails. Some matrix entries build only a sub-target (`kernel` or `libs`). If a `Build/tests/test-$(TARGET)` script exists, CI builds a disk image and runs it (often under an emulator); some have a `-prepare` companion script.

When changing core code, sanity-check against more than one CPU family — a change that compiles for Z80 may break 6502 or 68000.

## Repository Layout

- **`Kernel/`** — the OS kernel.
  - Core C in `Kernel/*.c`: `process.c`, `mm.c`, `swap.c`, `inode.c`, `filesys.c`, `tty.c`, `vt.c`, `select.c`, `timer.c`, `devio.c`, the `syscall_*.c` families, `start.c`, `kdata.c`. This is **shared, portable code** built for every target.
  - `Kernel/include/` — core kernel headers (`kernel.h`, `kdata.h`, `tty.h`, `page.h`, ...).
  - `Kernel/cpu-<arch>/` — per-CPU code (context switch `tricks`, crt0, ABI glue, usermem copy routines).
  - `Kernel/platform/platform-<target>/` — **per-machine port** (see below).
  - `Kernel/dev/` — shared device drivers (IDE, SD, SCSI, floppy, RTC, etc.) plus machine-bus subdirs (`rcbus/`, `80bus/`, `zx/`, `cpc/`, `net/`, ...). Drivers are *opt-in per platform* — there is no automatic driver registration.
  - `Kernel/PORTING` — the authoritative, detailed guide to porting/configuring a platform (CONFIG_* options, required asm/C hooks, disk geometry, swap, interrupts). Read this before touching platform code.
- **`Library/`** — userspace C library and link scripts. `Library/libs/Makefile.<CPU>` builds the C library per CPU; `Library/include/` has libc headers (with per-CPU subdirs). Built and `install`ed into the tree before apps.
- **`Applications/`** — userspace programs (`util`, V7 `cmd`/`sh`, games, `CC`, assembler, `ed`/`ue`, networking `netd`/`dw`, CP/M tools, emulators, ...). Driven by `Applications/Makefile`, each subdir built with `Makefile.$(USERCPU)`.
- **`Standalone/`** — host-side tools, notably `filesystem-src/build-filesystem` used by `make diskimage`.
- **`Tools/`** — `build-<CPU>` scripts invoked by the top-level `tools` target to prepare per-CPU build helpers.
- **`Target/`** — `rules.<CPU>` make fragments with per-CPU build rules.
- **`Build/`** — generated/host build infrastructure (`tools/`, `tests/`, `platforms/`, `rules/`).
- **`docs/`** — design documentation (Sphinx `.rst` + `.md`). High-value reads: `Intro.md`, `MemoryManagement.md`, `Process.rst`, `TTY.rst`, `VT.rst`, `DeviceDrivers.md`, `Interrupts.md`, `Platforms.md`, `DevPlatforms.md`, the ABI docs (`Z80ABI.md`, `M68000.md`, `65C816.md`, `68HC11ABI.md`), `Tickless.md`, `BankedZ80.md`.
- **`GUI/`, `Patches/`, `Images/`** — GUI bits, toolchain patches, and build output.

### Anatomy of a platform port (`Kernel/platform/platform-<target>/`)

A typical port contains: `target.mk` (exports `CPU`), `Makefile`, `config.h` and `kernel.def` (CONFIG_* options, memory layout, device counts), `crt0.s` + `commonmem.s` + `tricks.s` (low-level asm: startup, common area, context switch), `main.c` (`pagemap_init`, `platform_idle`, ...), `devices.c` (`dev_tab`, `validdev`, `device_init`), `devtty.c` (tty I/O hooks), plus machine-specific asm and a linker config. New ports are made by cloning the closest existing platform and adjusting it (see `Kernel/PORTING`).

## Coding Conventions (core/shared code)

`CodingStyle.md` is descriptive, not prescriptive, but the constraints below are real because they reflect the weakest compilers/CPUs in the matrix. They apply to **core tree code built for every target**; target-specific and imported code may relax them.

- **No floating point** and **no long division** in kernel code.
- **No `//` comments** and **no `(void)foo()` cast-to-void** — not all compilers support them.
- **All identifiers must be unique within the first 14 characters.**
- **Keep any single stack frame under 256 bytes** (cc65 / Z80 / 8085 / 6800 limits).
- Prefer **unsigned** arithmetic; sign extension and signed compares are expensive on several targets.
- Use **`uint_fast8_t`** (not `uint8_t`) for scalars/loop counters; reserve `uint8_t` for arrays.
- Pre-compute loop-limit expressions; keep one active pointer at a time (limited index registers). The kernel clusters related fields into arrays-of-structs for this reason.
- Custom annotations (defined per-target, may expand to nothing): `__packed`, `barrier()`, `inline`, `__fastcall`, `staticfast`, `regptr`, `used(x)`. Use `staticfast`/`regptr` deliberately — they trade re-entrancy/registers for speed on specific CPUs.
- Indentation is migrating toward 8-char tabs for core code; match the surrounding file.

## Contribution Rules

From `ContributionRules`:
- **GitHub Copilot–generated ("laundered") code is not accepted.**
- Contributions are assumed to be under the project's existing license; you must have the right to grant it.
- No dependencies on proprietary toolchains. Non-free deps are only acceptable for redistributable historical objects or creative works (e.g. games, the BCPL environment).

## Status / Notes

The README warns the Z80 side is mid-migration to the new Fuzix compiler/linker/kernel and may need bleeding-edge external tools; non-Z80 work is generally fine. `STATUS.md` and `ReleaseNotes.md` track per-area progress and what's missing (e.g. ptrace, large filesystems, full select/poll, TCP/IP in progress).
