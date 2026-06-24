# Technical-debt inventory

A refreshable index of technical debt across the FUZIX tree. It has two halves:

1. **In-code work markers** (`FIXME`, `TODO`, `XXX`, `HACK`) — counted and
   bucketed so the highest-leverage items (the portable core compiled for every
   one of the ~130 targets) are visible rather than buried across hundreds of
   files.
2. **Structural / architectural debt** — bigger items that no single marker
   captures: build-system coupling, bitrotted ports, unverified drivers, and
   missing subsystems.

It is a snapshot, not a contract. Regenerate the numbers before relying on them.

## How to regenerate

Counts are *occurrences* of the markers in C sources/headers (`*.c`, `*.h`).
Add `-g '*.s' -g '*.S'` to include assembly.

```sh
PAT='\b(FIXME|TODO|XXX|HACK)\b'
cm() { rg --count-matches --no-filename -e "$PAT" -g '*.c' -g '*.h' "$1" \
        | awk '{s+=$1} END{print s+0}'; }
cm .                                   # whole-tree grand total
cm Kernel; cm Library; cm Applications # per top-level tree
cm Kernel/mm; cm Kernel/dev; cm Kernel/platform   # kernel buckets
```

To list items in the portable core with file and line:

```sh
rg -n -e '\b(FIXME|TODO|XXX|HACK)\b' -g 'Kernel/*.c' -g 'Kernel/*.h' .
```

## Whole-tree snapshot

Scope: `*.c` / `*.h`. **Grand total: 1796 markers across 714 files.**

| Tree | Count | Notes |
|---|---:|---|
| `Kernel/` | 908 | The OS itself; see the kernel breakdown below. |
| `Applications/` | 798 | Userspace programs — mostly imported/ported code (see below). |
| `Library/` | 75 | libc + per-CPU link glue. |
| `Standalone/` | 9 | Host-side `build-filesystem` / `mkftl` tooling. |
| `GUI/` | 6 | |

The two big trees, `Kernel/` and `Applications/`, are *not* equal in priority:
markers in the portable kernel core ripple across the whole CPU matrix, whereas
most `Applications/` markers sit in self-contained, often third-party-derived
programs that are only built where used.

## Kernel breakdown

Scope: `*.c` / `*.h` under `Kernel/`. **Total: 908.**

| Bucket | Path | Count | Notes |
|---|---|---:|---|
| **Core kernel** | `Kernel/*.c`, `Kernel/*.h` | 64 | Portable code built for every target — highest leverage. |
| Memory management | `Kernel/mm/` | 45 | Bank/flat allocators, shared across MMU-less ports. |
| Shared drivers | `Kernel/dev/` | 114 | Of which `dev/net/`: 30. |
| Core headers | `Kernel/include/` | 15 | |
| CPU glue | `Kernel/cpu-*/` | 10 | (`.c`/`.h`; much per-CPU work lives in `.s`/`.S`.) |
| Per-platform | `Kernel/platform/` | 644 | Mostly target-specific; triage per port. |
| Library | `Kernel/lib/` | 4 | |
| Host tools | `Kernel/tools/` | 12 | Build-time host code, not on-target. |

The per-platform bucket dominates the raw count but is the *lowest* priority for
a cross-cutting cleanup: each marker is scoped to one machine and is best handled
by whoever owns that port. The core, mm, dev and include buckets (240 markers)
are where a change ripples across the whole matrix.

### Core hotspots

Files with the most core markers (`Kernel/*.c`):

| File | Count | Theme |
|---|---:|---|
| `Kernel/filesys.c` | 7 | Permission checks, efficiency (big-block-size now in docs/FilesystemExtents.md). |
| `Kernel/devio.c` | 9 | Buffer-cache locking, sleeping I/O, 32-bit safety. |
| `Kernel/tty.c` | 8 | IRQ races, `select` support, queue batching. |
| `Kernel/syscall_proc.c` | 5 | Process syscalls. |
| `Kernel/inode.c` | 5 | Inode lookup duplication, bread hinting. |

### Representative core items

These show the *kind* of work outstanding in the portable core. Each is
`file:line` against this snapshot — re-run the listing command above for the
authoritative set.

- Concurrency / I/O model (recurring theme — the kernel assumes block I/O does
  not reschedule; several markers anticipate relaxing that):
  - `Kernel/devio.c:40` — "need to add locking to this for the sleeping case, and a hash for ..."
  - `Kernel/devio.c:292` — "Once we support sleeping on disk I/O this goes away ..."
  - `Kernel/tty.c:41` — "fix race of timer versus the ptimer_insert to psleep_flags_io"
  - `Kernel/tty.c:359` — "IRQ race"
  - `Kernel/select.c:221` — "lock against time race"
- 32-bit / large-filesystem correctness:
  - `Kernel/devio.c:690` — "not 32-bit safe"
  - `Kernel/syscall_fs2.c:353` — "needs updating once we pack top bits ..."
  - (bigger block size / extents: dependency map and remaining work are now in
    `docs/FilesystemExtents.md`)
- Incomplete subsystems:
  - `Kernel/tty.c:720` / `Kernel/select.c:25` — `select`/socket support gaps.
  - `Kernel/audio.c:53` — "read/write for DSP devices" not implemented.
  - `Kernel/network.c:160`, `Kernel/network.c:188` — socket-stack review/cleanup.
- Code-generation / efficiency notes (matter because of the weak toolchains in
  the matrix):
  - `Kernel/filesys.c:448` — "generates crap code on most compilers so we probably ought to ..."
  - `Kernel/inode.c:85` — "we end up doing the ino - udata comparison 3 times, fix this"

## Userspace breakdown (`Applications/`, `Library/`)

Scope: `*.c` / `*.h`. The `Applications/` markers concentrate in large, mostly
imported programs; treat them as per-program debt owned with that program, not as
cross-cutting core work.

| Program | Count | Notes |
|---|---:|---|
| `Applications/CC/` | 251 | The C compiler — by far the largest single sink. |
| `Applications/games/` | 233 | Ported games (BSD/V7 lineage). |
| `Applications/assembler/` | 86 | |
| `Applications/util/` | 71 | Core coreutils-style utilities — the most worth triaging. |
| `Applications/V7/` | 29 | V7 `cmd`/`sh`. |
| `Applications/netd/` | 20 | Network daemon (TCP/IP still in progress). |
| `Applications/cpnet/`, `ld09/`, `MWC/`, `basic/`, `as09/`, `plato/` | 10–19 each | |

`Library/` (75): libc sources (`Library/libs`, 47), headers (`Library/include`,
20), and host tools (`Library/tools`, 8). These are higher-leverage than the
app totals because libc is linked into every userspace binary on every target.

## Structural / architectural debt (beyond in-code markers)

Items that won't show up in a marker grep but are real, tracked debt. The living
trackers are `STATUS.md` and `ReleaseNotes*.md`; this list points at the
load-bearing ones.

- **Build-system coupling.** The top-level `Makefile:108` carries
  `# FIXME: we should make it possible to do things entirely without /opt/fcc` —
  the build hardcodes the `/opt/fcc` toolchain prefix on `PATH`. More broadly,
  there is *no single compiler*: each CPU family needs a different, externally
  installed toolchain (see `BUILD_REQUIREMENTS.md`), and the m68k distro
  toolchains are broken (CI uses a kernel.org crosstool, see `README.68000.md`).
- **Z80 mid-migration.** Per `README.md`, the Z80/Z180 side is mid-move to the
  new Fuzix compiler/linker/kernel and may require bleeding-edge external tools;
  some banked kernels still need the patched `EtchedPixels/sdcc280`.
- **Toolchain-driven design limits** (`README.md` "Tool Issues"): 6809 gcc and
  cc65 lack 64-bit `long long`, which blocks a sane 64-bit `time_t` on those
  targets; cc65 can't handle larger stack objects and lacks float; a "proper"
  65C816 C compiler is still wanted.
- **Bitrotted / retired ports.** `MSP430` boots are bitrotted
  (`README.md:74`); `platform-socz80` needs adapting to the BANK16K scheme
  (`Kernel/platform/platform-socz80/README:17`); `ReleaseNotes-0.3.md` and
  `STATUS.md` list further retired/bitrotted entries (e.g. MSX1 MegaMem).
- **PicoCalc LCD/keyboard drivers are unverified scaffolding.** `devlcd.c`,
  `devkbd.c` and `fontdata8x8.c` compile but have never run on hardware; the
  panel init sequence/pixel format and the keyboard keymap/pins/bus are marked
  `TODO`. Audio (`do_beep` stub), an RTC driver, and a `/dev/i2c` userspace
  interface are missing. Full bring-up checklist in `docs/PicoCalc.md`.
- **Missing / in-progress subsystems** (`README.md` "What Key Features Are
  Missing"): `ptrace` and most of `ulimit`; root-reserved disk blocks; banked
  executables; TCP/IP (in progress); `select`/`poll` (in progress, matches the
  kernel `select.c`/`tty.c` markers above); filesystems larger than 32MB; a
  smarter scheduler; and disk block/inode allocator optimisations. The
  bigger-block-size / extent work that several of these depend on has its own
  dependency map and staged plan in `docs/FilesystemExtents.md`.
- **Concurrency model assumption.** The kernel is built around block I/O and
  user-memory access never blocking/rescheduling (uniprocessor, cooperative).
  The cluster of `devio.c`/`tty.c`/`select.c` locking markers is the cost of
  relaxing that assumption later, and is best treated as one coherent effort.

## Triage guidance

1. **Core / mm / include first.** A fix there is validated across the CI matrix
   and benefits every port. `Library/` (libc) is the userspace equivalent.
2. **Group by theme, not by file.** The concurrency-and-sleeping-I/O markers, the
   32-bit/large-FS markers, and the missing-`select`/socket markers each form a
   coherent piece of work; tackling a theme beats scattered one-line fixes.
3. **Per-program userspace debt** (CC, games, assembler) is owned with that
   program; don't fold it into core cleanups.
4. **Respect the coding constraints in `CLAUDE.md` / `CodingStyle.md`** when
   acting on any of these (no floating point, no long division, 14-char unique
   identifiers, stack frames under 256 bytes, prefer unsigned).
5. **Validate against more than one CPU family.** A core change that builds for
   Z80 can still break 6502 or 68000; see `docs/Testing.md` and the CI matrix.
6. **Per-platform markers** should be raised with, or fixed by, the port owner.
