#!/bin/bash
# audit-vm-init.sh PROGRAM [LLVM_BIN]: checks the linked decoder VM program (decoder_vm_init, arm64, unstripped, from
# the build's intermediates) for what the source cannot show. Exit 0 when every check passes.
#   1. BTI and PAC: the program is marked with both (the kernel guards its pages only then).
#   2. No libhevc assembly: no *_av8 symbol but ihevcd_init_function_ptr_av8, which vm/fmt_heif.cpp defines.
#   3. No setjmp that saves the signal mask: nothing calls setjmp, sigsetjmp or __sigsetjmp (vm/decoder_vm.cpp
#      sends every setjmp to _setjmp).
#   4. First-use system calls: every function that calls pthread_once, __cxa_guard_acquire, gettid,
#      sigprocmask, sched_getaffinity or clock_gettime is listed and compared with audit-vm-init.allow, where each
#      known one carries the reason a worker never makes that call (warmed up in the broker, broker only, unreachable).
#      A new caller fails the audit until it is understood and added.
#   5. No test hooks: the product program has none of the test build's functions or strings (hooks, the bench, the
#      serial port broker), so a wrong compile flag cannot ship them unseen. TEST_PROGRAM=1 inverts it, to show the
#      check finds them in decoder_vm_init_test.
set -u
P=${1:?program}
B=${2:-}
tool() { if [ -n "$B" ]; then echo "$B/$1"; else echo "$1"; fi; }
HERE=$(cd "$(dirname "$0")" && pwd)
rc=0
say() { echo "$1"; }
bad() { echo "FAIL $1"; rc=1; }

notes=$("$(tool llvm-readelf)" -n "$P" 2>/dev/null)
if echo "$notes" | grep -q "aarch64 feature: BTI, PAC"; then say "ok   BTI and PAC marked"; else bad "BTI and PAC marking"; fi

av8=$("$(tool llvm-nm)" "$P" | awk '{print $NF}' | grep '_av8$' | grep -v '^ihevcd_init_function_ptr_av8$')
if [ -z "$av8" ]; then say "ok   no libhevc assembly"; else bad "libhevc assembly linked: $(echo $av8 | cut -c1-200)"; fi

dis=$(mktemp) || { echo "FAIL no temporary file"; exit 2; }
trap 'rm -f "$dis"' EXIT
"$(tool llvm-objdump)" -d --no-show-raw-insn "$P" > "$dis" && [ -s "$dis" ] || { echo "FAIL no disassembly"; exit 2; }
callers() {  # target symbol: the functions with a direct call or branch to it
  awk -v T="<$1>" '/^[0-9a-f]+ <.*>:$/ {f = substr($2, 2, length($2) - 3)} ($0 ~ /\tbl?\t/ && index($0, T)) {print f}' \
    "$dis" | sort -u
}
# bionic's own setjmp and _setjmp are sigsetjmp with and without the mask. Nothing else may call any of them, and
# nothing may call setjmp (every call goes to _setjmp, through __wrap_setjmp).
for t in setjmp sigsetjmp __sigsetjmp; do
  c=$(callers $t | grep -v -x -e _setjmp -e setjmp)
  if [ -z "$c" ]; then say "ok   nothing calls $t"; else bad "$t called by: $(echo $c | cut -c1-200)"; fi
done
[ -n "$(callers _setjmp | grep -x __wrap_setjmp)" ] && say "ok   setjmp goes to _setjmp" || bad "no __wrap_setjmp to _setjmp"

found=$(for t in pthread_once __cxa_guard_acquire gettid sigprocmask __rt_sigprocmask sched_getaffinity clock_gettime; do
  callers $t | sed "s/^/$t /"
done | sort -u)
allowed=$(grep -v '^#' "$HERE/audit-vm-init.allow" | awk 'NF >= 2 {print $1, $2}' | sort -u)
new=$(comm -23 <(echo "$found") <(echo "$allowed"))
gone=$(comm -13 <(echo "$found") <(echo "$allowed"))
if [ -z "$new" ]; then
  say "ok   first-use calls: $(echo "$found" | grep -c .) callers, all in audit-vm-init.allow"
else
  bad "first-use calls not in audit-vm-init.allow:"
  echo "$new" | sed 's/^/       /'
fi
[ -z "$gone" ] || { echo "note allowed but no longer present:"; echo "$gone" | sed 's/^/       /'; }
hooks=$("$(tool llvm-nm)" -C --format=just-symbols "$P" | grep -E '(^|::)(hook_report|hook_scan|bench|serve_port)\(' | sort -u)
for t in "--bench" "/dev/decoder-port" "bench seccomp log"; do
  LC_ALL=C grep -a -q -F -e "$t" "$P" && hooks="$hooks string:$t"
done
if [ "${TEST_PROGRAM:-0}" = 1 ]; then
  [ -n "$hooks" ] && say "ok   test program carries its hooks (the check sees them)" || bad "no hooks found in the test program"
elif [ -z "$hooks" ]; then
  say "ok   no test hooks"
else
  bad "test hooks in the product program: $(echo $hooks | cut -c1-200)"
fi
exit $rc
