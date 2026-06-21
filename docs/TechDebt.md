# Kernel technical-debt inventory

This is a refreshable index of in-code work markers (`FIXME`, `TODO`, `XXX`,
`HACK`) in the kernel tree. It exists so that the highest-impact items — those
in the **portable core** that is compiled for every one of the ~130 targets —
are visible and triageable, rather than buried across hundreds of files.

It is a snapshot, not a contract. Regenerate the numbers before relying on them.

## How to regenerate

Counts below are *occurrences* of the markers in C sources and headers
(`*.c`, `*.h`) under `Kernel/`:

```sh
PAT='\b(FIXME|TODO|XXX|HACK)\b'
cm() { rg --count-matches --no-filename -e "$PAT" -g '*.c' -g '*.h' "$1" \
        | awk '{s+=$1} END{print s+0}'; }
cm Kernel            # grand total
cm Kernel/mm; cm Kernel/dev; cm Kernel/platform   # per bucket
```

To list the core items with file and line:

```sh
rg -n -e '\b(FIXME|TODO|XXX|HACK)\b' -g 'Kernel/*.c' -g 'Kernel/*.h' .
```

## Snapshot

Scope: `*.c` / `*.h` under `Kernel/`. **Total: 895.**

| Bucket | Path | Count | Notes |
|---|---|---:|---|
| **Core kernel** | `Kernel/*.c`, `Kernel/*.h` | 66 | Portable code built for every target — highest leverage. |
| Memory management | `Kernel/mm/` | 45 | Bank/flat allocators, shared across MMU-less ports. |
| Shared drivers | `Kernel/dev/` | 114 | Of which `dev/net/`: 30. |
| Core headers | `Kernel/include/` | 15 | |
| CPU glue | `Kernel/cpu-*/` | 10 | |
| Per-platform | `Kernel/platform/` | 629 | Mostly target-specific; triage per port. |
| Library | `Kernel/lib/` | 4 | |
| Host tools | `Kernel/tools/` | 12 | Build-time host code, not on-target. |

The per-platform bucket dominates the raw count but is the *lowest* priority for
a cross-cutting cleanup: each marker is scoped to one machine and is best handled
by whoever owns that port. The core, mm, dev and include buckets (240 markers)
are where a change ripples across the whole matrix.

## Core hotspots

Files with the most core markers (`Kernel/*.c`):

| File | Count | Theme |
|---|---:|---|
| `Kernel/filesys.c` | 9 | Big-block-size FS support, permission checks, efficiency. |
| `Kernel/devio.c` | 9 | Buffer-cache locking, sleeping I/O, 32-bit safety. |
| `Kernel/tty.c` | 8 | IRQ races, `select` support, queue batching. |
| `Kernel/syscall_proc.c` | 5 | Process syscalls. |
| `Kernel/inode.c` | 5 | Inode lookup duplication, bread hinting. |

## Representative core items

These are quoted to show the *kind* of work outstanding in the portable core.
Each is `file:line` against this snapshot — re-run the listing command above for
the authoritative set.

- Concurrency / I/O model (recurring theme — the kernel assumes block I/O does
  not reschedule; several markers anticipate relaxing that):
  - `Kernel/devio.c:40` — "need to add locking to this for the sleeping case, and a hash for ..."
  - `Kernel/devio.c:292` — "Once we support sleeping on disk I/O this goes away ..."
  - `Kernel/tty.c:41` — "fix race of timer versus the ptimer_insert to psleep_flags_io"
  - `Kernel/tty.c:359` — "IRQ race"
  - `Kernel/select.c:221` — "lock against time race"
- 32-bit / large-filesystem correctness:
  - `Kernel/devio.c:690` — "not 32-bit safe"
  - `Kernel/filesys.c:712` — "When we implement the rest of the bigger block size fs support ..."
  - `Kernel/syscall_fs2.c:353` — "needs updating once we pack top bits ..."
- Incomplete subsystems:
  - `Kernel/tty.c:720` / `Kernel/select.c:25` — `select`/socket support gaps.
  - `Kernel/audio.c:53` — "read/write for DSP devices" not implemented.
  - `Kernel/network.c:160`, `Kernel/network.c:188` — socket-stack review/cleanup.
- Code-generation / efficiency notes (matter because of the weak toolchains in
  the matrix):
  - `Kernel/filesys.c:448` — "generates crap code on most compilers so we probably ought to ..."
  - `Kernel/inode.c:85` — "we end up doing the ino - udata comparison 3 times, fix this"
  - `Kernel/filesys.c:411` — "add strncpy and use for this"

## Triage guidance

1. **Core / mm / include first.** A fix there is validated across the CI matrix
   and benefits every port.
2. **Group by theme, not by file.** The concurrency-and-sleeping-I/O markers, the
   32-bit/large-FS markers, and the missing-`select`/socket markers each form a
   coherent piece of work; tackling a theme is more valuable than scattered
   one-line fixes.
3. **Respect the coding constraints in `CLAUDE.md` / `CodingStyle.md`** when
   acting on any of these (no floating point, no long division, 14-char unique
   identifiers, stack frames under 256 bytes, prefer unsigned).
4. **Validate against more than one CPU family.** A core change that builds for
   Z80 can still break 6502 or 68000; see `docs/Testing.md` and the CI matrix.
5. **Per-platform markers** should be raised with, or fixed by, the port owner.
