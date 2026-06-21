# Shared helpers for Build/tests/test-<target> scripts.
#
# Source this from a test script:
#	. "$(dirname "$0")/common.sh"
#
# A platform test boots its disk image under an emulator and succeeds only if
# the marker below appears in the captured log. The marker is printed by the
# platform's userspace/rc.ci_testing (installed as rc by the matching
# test-<target>-prepare script) once its checks have run.

MARKER="Testing done!"

# require_image PATH
#	Fail unless the disk image exists. Build it first with `make diskimage`.
require_image() {
	if [ ! -e "$1" ]; then
		echo "No image file $1"
		exit 1
	fi
}

# require_files FILE...
#	Fail unless every named file exists. Use for emulator ROMs and other
#	host-side prerequisites the test cannot supply itself.
require_files() {
	for f in "$@"; do
		if [ ! -e "$f" ]; then
			echo "Missing required file $f"
			exit 1
		fi
	done
}

# run_test LOGFILE CMD [ARG...]
#	Run the emulator (CMD plus ARGs), tee its combined output to LOGFILE,
#	then succeed only if MARKER is present. The emulator is expected to exit
#	on its own (e.g. a timeout or the motor relay turning off); this helper
#	does not impose its own timeout.
run_test() {
	logfile="$1"
	shift
	echo "Starting $1 $(date)"
	"$@" 2>&1 | tee "$logfile"
	echo "Emulator done $(date)"
	grep -q "$MARKER" "$logfile"
}
