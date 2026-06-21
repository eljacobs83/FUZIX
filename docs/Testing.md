# Automated platform testing

FUZIX has a lightweight harness for booting a built disk image under an emulator
in CI and checking that userspace comes up and runs. It is deliberately simple:
the kernel and userspace produce a known text marker on a console the emulator
can capture, and the host side greps the captured log for that marker.

This document describes the harness and how to add a test for a new platform.

## How a target gets discovered

Run `make list-targets` to print every platform under `Kernel/platform/` with
its CPU, and `make help` for the common build goals. The continuous integration
matrix in `.github/workflows/continuous-integration.yml` builds a representative
subset of these targets on every push and pull request.

## The pieces

A platform test is made of up to four small files:

1. **`Kernel/platform/platform-<target>/userspace/rc.ci_testing`** — a boot
   script that runs some self-checks and, when they pass, prints exactly:

   ```
   Testing done!
   ```

   and then stops the machine so the emulator exits. The Dragon example stops
   the machine by turning the cassette motor relay off, which the emulator is
   told to treat as a shutdown (see `-timeout-motoroff` below). See
   `Kernel/platform/platform-dragon-nx32/userspace/rc.ci_testing` for the
   reference content (it exercises `dc`, a shell pipeline, and `fforth`).

2. **`Build/tests/test-<target>-prepare`** — a one-line script that installs the
   CI rc file as the real `rc` used when the filesystem image is built, e.g.:

   ```sh
   #!/bin/sh
   cp Kernel/platform/platform-<target>/userspace/rc.ci_testing \
      Kernel/platform/platform-<target>/userspace/rc
   ```

3. **`Build/tests/test-<target>`** — the test itself. It boots
   `Images/<target>/disk.img` under the emulator and succeeds only if the marker
   appears. Common logic lives in `Build/tests/common.sh`, so a test is short:

   ```sh
   #!/bin/sh
   . "$(dirname "$0")/common.sh"

   IMAGE=Images/<target>/disk.img
   require_image "$IMAGE"
   require_files /path/to/rom            # optional emulator ROMs

   run_test test-<target>.log \
       your-emulator --headless --disk "$IMAGE"
   ```

   `Build/tests/test-TEMPLATE.sh` is a ready-to-copy starting point.

4. **`Kernel/platform/platform-<target>/rules.mk`** (optional) — if the kernel
   needs a CI-only hook, gate it on `CI_TESTING`. The Dragon Mooh port, for
   example, enables a simulated CRT9128 serial console and redirects the boot
   console to it only under CI:

   ```make
   ifneq ($(CI_TESTING),)
   CROSS_CCOPTS += -DCRT9128SIM=1 -DBOOT_TTY=514
   endif
   ```

## `Build/tests/common.sh`

Sourced by the test scripts. It provides:

- `require_image PATH` — fail unless the disk image exists (build it with
  `make diskimage` first).
- `require_files FILE...` — fail unless every host prerequisite (emulator ROMs,
  etc.) exists.
- `run_test LOGFILE CMD [ARG...]` — run the emulator, tee combined output to
  `LOGFILE`, and exit success only if the `Testing done!` marker is present. The
  emulator is expected to exit on its own (a wall-clock timeout and/or a halt
  condition); `run_test` does not impose its own timeout.

The single source of truth for the marker string is `MARKER` in `common.sh`.

## How CI runs it

In the `target testing` step of the workflow, for each matrix target:

1. If `Build/tests/test-<target>` exists, run `test-<target>-prepare` (if
   present), then `make diskimage`, then `test-<target>`.
2. Otherwise log `No automated test for <target> (build-only)` so it is visible
   that the job only checked the build.

Targets that need a CI-only kernel hook also pass `CI_TESTING=1` to `make` and
install the emulator package in the `install build deps` step (see the
`dragon-mooh|dragon-nx32|multicomp09` case for the `xroar` example).

## Adding a test: checklist

1. Add `userspace/rc.ci_testing` to your platform that prints `Testing done!`
   and then halts.
2. Add `Build/tests/test-<target>-prepare` to install it as `rc`.
3. Copy `Build/tests/test-TEMPLATE.sh` to `Build/tests/test-<target>`, fill in
   the image path and emulator invocation, and `chmod +x` it.
4. If a CI-only console/hook is required, gate it on `CI_TESTING` in the
   platform `rules.mk`.
5. Add the target to the CI matrix, installing the emulator package and passing
   `flags=CI_TESTING=1` if needed.
6. Verify locally: `make TARGET=<target> diskimage`, run
   `./Build/tests/test-<target>-prepare`, rebuild the image, then
   `./Build/tests/test-<target>` and confirm it exits 0.

## Worked example

`dragon-mooh` is the reference implementation. It builds with `CI_TESTING=1`,
boots under `xroar` with a simulated CRT9128 serial console captured on stderr,
runs the shared `rc.ci_testing`, and greps for the marker. Read
`Build/tests/test-dragon-mooh` alongside this document.
