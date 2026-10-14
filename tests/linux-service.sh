#!/usr/bin/env bash
# Service lifecycle on a Linux machine with systemd: install, start/stop, crash recovery,
# manual list, uninstall. It really installs the service, so run it only on a disposable
# machine (a CI runner or a container); it refuses to run otherwise.
#
#   RUNET_TEST_DISPOSABLE=1 sudo -E tests/linux-service.sh [path/to/runet-direct]
#
# RUNET_TEST_RIPE_FILE=/path/to/delegated-file makes the run offline.
set -euo pipefail

[[ ${RUNET_TEST_DISPOSABLE:-} == 1 ]] || { echo "set RUNET_TEST_DISPOSABLE=1 to confirm this machine can be modified"; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 2; }
BIN=$(realpath "${1:-target/debug/runet-direct}")
INSTALLED=/usr/local/bin/runet-direct
pass=0
step() { printf '\n== %s\n' "$*"; }
ok()   { pass=$((pass + 1)); printf '   ok: %s\n' "$*"; }
die()  { printf '   FAIL: %s\n' "$*"; journalctl -u runet-direct --no-pager -n 30 2>/dev/null || true; exit 1; }
expect()     { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else die "$d  ($*)"; fi; }
expect_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then die "$d  ($*)"; else ok "$d"; fi; }
code_is() { # code_is <expected> <description> <command...>
  local want=$1 d=$2 got; shift 2
  set +e; "$@" >/dev/null 2>&1; got=$?; set -e
  [[ $got -eq $want ]] && ok "$d (exit $got)" || die "$d: expected exit $want, got $got"
}
wait_for() { local t=$1 d=$2; shift 2; for ((i = 0; i < t * 5; i++)); do "$@" >/dev/null 2>&1 && { ok "$d"; return; }; sleep 0.2; done; die "$d (timed out after ${t}s)"; }
routes() { ip -4 route show table 900 2>/dev/null | wc -l; }

cleanup() { "$INSTALLED" uninstall --purge >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "before installing"
code_is 4 "status says not installed" "$BIN" status
[[ $(routes) -eq 0 ]] || die "table 900 is not empty on this machine"

if [[ -n ${RUNET_TEST_RIPE_FILE:-} ]]; then
  mkdir -p /etc/runet-direct
  printf '[ru]\nsource_url = "file://%s"\nmin_prefixes = 100\n' "$RUNET_TEST_RIPE_FILE" > /etc/runet-direct/config.toml
fi

step "install"
"$BIN" install
expect "binary copied to $INSTALLED" test -x "$INSTALLED"
expect "unit file exists" test -f /etc/systemd/system/runet-direct.service
expect "service active" systemctl is-active --quiet runet-direct
expect "service enabled at boot" systemctl is-enabled --quiet runet-direct
expect "rule 2500 present" bash -c "ip -4 rule show | grep -q '^2500:'"
[[ $(routes) -gt 1000 ]] && ok "table 900 filled ($(routes) routes)" || die "table 900 has only $(routes) routes"
code_is 0 "status is healthy" "$INSTALLED" status
code_is 0 "check says the whole setup is ok" "$INSTALLED" check
"$INSTALLED" status --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['service']['running'] and d['health']['healthy'], d" && ok "status --json agrees"

step "stop keeps routes; start brings the daemon back"
"$INSTALLED" stop
expect_not "service not active" systemctl is-active --quiet runet-direct
code_is 3 "status says installed but not running" "$INSTALLED" status
[[ $(routes) -gt 1000 ]] && ok "routes stay after stop" || die "routes vanished on stop"
"$INSTALLED" start
expect "service active again" systemctl is-active --quiet runet-direct
"$INSTALLED" restart
expect "service active after restart" systemctl is-active --quiet runet-direct

step "crash recovery and lost rule"
pid=$(systemctl show -p MainPID --value runet-direct)
kill -9 "$pid"
wait_for 20 "systemd restarts a killed daemon" bash -c "[[ \$(systemctl show -p MainPID --value runet-direct) -ne $pid && \$(systemctl show -p MainPID --value runet-direct) -ne 0 ]]"
ip -4 rule del priority 2500 from all lookup 900
wait_for 15 "deleted rule is restored by the running daemon" bash -c "ip -4 rule show | grep -q '^2500:'"

step "enable/disable"
"$INSTALLED" disable
expect_not "disabled at boot" systemctl is-enabled --quiet runet-direct
"$INSTALLED" enable
expect "enabled at boot" systemctl is-enabled --quiet runet-direct

step "manual list through the CLI"
"$INSTALLED" add 203.0.113.7 >/dev/null
expect "203.0.113.7 is direct" "$INSTALLED" check 203.0.113.7
"$INSTALLED" remove 203.0.113.7 >/dev/null
"$INSTALLED" list | grep -q 203.0.113.7 && die "entry still listed" || ok "entry removed from the list"

step "uninstall"
"$INSTALLED" uninstall --purge
expect_not "unit file gone" test -e /etc/systemd/system/runet-direct.service
expect_not "binary gone" test -e "$INSTALLED"
[[ $(routes) -eq 0 ]] && ok "table 900 empty" || die "table 900 still has routes"
expect_not "rule removed" bash -c "ip -4 rule show | grep -q '^2500:'"
expect_not "config removed (--purge)" test -e /etc/runet-direct
trap - EXIT

printf '\nALL PASSED (%d checks)\n' "$pass"
