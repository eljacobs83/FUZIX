#!/bin/sh
#
# Template for a platform automated test. This file is NOT run by CI (its name
# does not match any target). To add a test for a real platform:
#
#   1. Add a userspace/rc.ci_testing to your platform that runs some checks and
#      prints exactly "Testing done!" when they pass, then stops the machine
#      (e.g. by turning the motor relay off so the emulator's -timeout-motoroff
#      fires). See Kernel/platform/platform-dragon-nx32/userspace/rc.ci_testing.
#
#   2. Copy this file to Build/tests/test-<target> (make it executable) and a
#      one-line Build/tests/test-<target>-prepare that installs rc.ci_testing
#      as rc. See Build/tests/test-dragon-mooh{,-prepare} for a worked example.
#
#   3. If the kernel needs CI-only hooks (e.g. a serial console the emulator can
#      capture), gate them on CI_TESTING in the platform rules.mk and add the
#      target to .github/workflows/continuous-integration.yml with
#      flags=CI_TESTING=1 and the emulator package installed.
#
# See docs/Testing.md for the full workflow.

. "$(dirname "$0")/common.sh"

IMAGE=Images/<target>/disk.img
LOGFILE=test-<target>.log

# Bail out early if the image or any host prerequisite (ROMs, ...) is missing.
require_image "$IMAGE"
# require_files /path/to/rom1 /path/to/rom2

# Run the emulator headless. It must exit on its own (a wall-clock timeout and/or
# a "machine halted" condition). run_test tees output to LOGFILE and succeeds
# only if the "Testing done!" marker appears.
run_test "$LOGFILE" \
    your-emulator \
    --headless \
    --disk "$IMAGE"
