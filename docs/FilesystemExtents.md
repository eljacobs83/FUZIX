# Bigger block sizes / filesystem extents

This is a design + dependency note for the **unfinished** "bigger block size"
filesystem work referenced by the `FIXME` in `Kernel/filesys.c` (`blk_alloc`) and
the `s_shift` ("Extent size") superblock field. It exists so the remaining work
is actionable and the open decisions are written down, rather than buried in a
one-line marker.

**Status: gated off and not usable today.** Every filesystem this kernel mounts
has `s_shift == 0` (512-byte blocks). The pieces below are partly built and
mutually inconsistent; treat this as a map, not a spec.

## What a "bigger block" is meant to be

A filesystem block (the unit the free list and inode block pointers count in) is
an **extent** of `1 << s_shift` physical 512-byte sectors:

| `s_shift` | block size | `mkfs -b` |
|---:|---:|---:|
| 0 | 512 | 512 |
| 1 | 1024 | 1024 |
| 2 | 2048 | 2048 |
| 3 | 4096 | 4096 |
| 4 | 8192 | 8192 |
| 5 | 16384 | 16384 |

The motivation is larger filesystems and less metadata overhead without widening
`blkno_t`: one block number addresses `2^shift` more bytes.

## What already exists

- **On-disk field.** `struct filesys.s_shift` (`Kernel/include/kernel.h`), also
  mirrored in `Library/include/sys/super.h` and `Standalone/fuzix_fs.h`.
- **`mkfs -b <bytes>`** (`Standalone/mkfs.c`) maps a byte size to a shift via
  `validate()` and writes `s_shift`.
- **Mount validation.** `fs_mount()` (`Kernel/filesys.c`) rejects a filesystem
  whose `s_shift > FS_MAX_SHIFT`.
- **The gate.** `FS_MAX_SHIFT` defaults to `0` (`Kernel/include/kernel.h`) and is
  `#ifndef`-overridable per target. While it is 0, mount rejects every
  `s_shift > 0` filesystem, so none of the unfinished paths below can execute.

## Why it does not work yet — the dependency chain (bottom-up)

1. **No runtime block size.** `BLKSIZE`, `BLKSHIFT`, `BLKMASK`, `BLKOFF`,
   `BLK_TO_OFFSET` are compile-time constants (`Kernel/include/blk512.h`,
   `blk400.h`) used in ~36 places across the core (`inode.c`, `filesys.c`,
   `swap.c`, `page.c`, `devio.c`, …). Nothing derives a size from `s_shift` at
   runtime. **This is the real first dependency** — everything else builds on it.
2. **Buffer-cache model decision (open).** The buffer cache holds fixed
   `BLKSIZE` (512-byte) buffers; `bdread`/`bdwrite` (`Kernel/devio.c`) transfer
   exactly `BLKSIZE`. Two options:
   - *Group sectors:* keep 512-byte buffers and treat an extent as `2^shift`
     consecutive sectors (cheap RAM — important on a 64 KB Z80; more buffer-cache
     traffic per block).
   - *Larger buffers:* make the buffer size track the block size (simpler FS
     math; costly/!infeasible on small machines, where a 16 KB buffer is absurd).
   The grouping option is the only one viable across the whole target matrix.
3. **Block ↔ offset mapping.** `mapcalc`/`bmap` (`Kernel/inode.c`, `blk512.c`)
   convert a file offset to a block and back assuming `BLKSIZE`. With extents the
   file-block → physical-sector step becomes `sector = block << s_shift` (read
   `2^shift` sectors), and `BLKOFF`/`BLK_TO_OFFSET` must use the runtime size.
4. **Extent allocation.** `blk_alloc()` (`Kernel/filesys.c`) returns a *single*
   number from the free list; there is no contiguous `2^shift`-sector
   reservation. Under the grouping model the free list must enumerate *extents*
   (base block numbers spaced by the extent), which is a `mkfs` + allocator
   contract, not just kernel code.
5. **Zero the whole extent.** `blk_alloc()` must clear all `2^shift` sectors of a
   freshly allocated extent. *(Plumbing for this is in place — see below.)*
6. **Directory & indirect math.** Sites like `BLKSIZE / DIR_LEN` (directory
   scan, `filesys.c`) and `BLKSIZE / 2` (indirect-pointer counts, `filesys.c`)
   assume the 512 layout and must use the runtime size.

## Known inconsistency to reconcile first

`mkfs` does **not** treat units consistently for `shift > 0`. In
`Standalone/mkfs.c`:

- it zeroes `s = fsize << shift` physical sectors (extent → sector scaling), but
- the free-list loop runs `for (j = fsize - 1; j > isize; --j)` and writes via
  `dwrite(j, …)` at sector `j * 512`, i.e. it frees **`fsize` sectors counted as
  blocks**, and places the root directory at sector `isize` after
  `isize <<= shift`.

So the free list ends up in a mix of extent and sector numbering. Before any
kernel work, decide the single canonical numbering (recommended: the free list
and inode block pointers store **extent numbers**; physical sector =
`extent << s_shift`) and make `mkfs`, `fsck`, and the kernel agree.

## What this change does (plumbing only — safe at `s_shift == 0`)

- Adds `fs_extent_blocks(dev)` in `Kernel/filesys.c` returning
  `1 << dev->s_shift` — a single canonical accessor for "blocks per extent".
- Makes `blk_alloc()` zero `fs_extent_blocks()` consecutive blocks from `newno`
  instead of one, resolving the historical FIXME. With `s_shift == 0` this loops
  exactly once and is byte-for-byte the previous behaviour, so it is a no-op on
  every filesystem any current target mounts.

It deliberately does **not** add the runtime size to the 36 `BLKSIZE` sites,
change the buffer-cache model, alter `mkfs`, or raise `FS_MAX_SHIFT` — those are
the larger, on-disk-semantics steps above.

> The `newno + i` run in `blk_alloc` assumes an extent is consecutive blocks in
> the free list's numbering. That is the natural reading, but it is only
> *exercised* once the model in "Known inconsistency" is settled and
> `FS_MAX_SHIFT` is raised; revisit it then.

## Suggested order to finish it

1. Settle and document the numbering model; fix `mkfs` (and `fsck`) to match.
2. Introduce a runtime block size/shift accessor and migrate the `BLKSIZE`
   sites, keeping the 512 fast path.
3. Implement extent-aware `mapcalc`/`bmap` and contiguous extent allocation.
4. Update directory/indirect math to the runtime size.
5. Only then raise `FS_MAX_SHIFT` on a target that can be **booted and tested** —
   this cannot be validated by CI build-only jobs, and a wrong block↔sector map
   silently corrupts filesystems. Test create/read/write/truncate/`fsck` on real
   or emulated hardware before enabling it anywhere.
