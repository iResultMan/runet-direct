#!/bin/bash
# Safe real-machine test of runet-direct on macOS. Run once as root:
#   sudo bash tests/macos-live.sh   (the binary must sit next to the script)
# It only ever routes documentation addresses (203.0.113.0/24, 198.51.100.7) and compares the number
# of existing routes through the gateway before and after, so the routes of other tools are untouched.
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
BIN=$DIR/runet-direct
LOG=$DIR/result.log
exec > >(tee "$LOG") 2>&1

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 2; }
[ -x "$BIN" ] || chmod +x "$BIN"

pass=0; fail=0
ok()   { pass=$((pass + 1)); echo "   ok: $*"; }
bad()  { fail=$((fail + 1)); echo "   FAIL: $*"; }
step() { echo; echo "== $*"; }
expect()     { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d  ($*)"; fi; }
expect_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d  ($*)"; else ok "$d"; fi; }
wait_for() { local t=$1 d=$2; shift 2; local i=0; while [ $i -lt $((t * 2)) ]; do "$@" >/dev/null 2>&1 && { ok "$d (after ~$((i / 2))s)"; return; }; sleep 0.5; i=$((i + 1)); done; bad "$d (timed out after ${t}s)"; }
has_route() { netstat -rn -f inet | grep -q "^$1 "; }
GW=$(netstat -rn -f inet | awk '$1=="default" && $4 ~ /^en/ {print $2; exit}')
via_gw() { netstat -rn -f inet | awk -v p="$1" -v g="$GW" '$1==p && $2==g {f=1} END {exit !f}'; }
others() { netstat -rn -f inet | awk -v g="$GW" '$2==g' | grep -v -E '^(203\.0\.113|198\.51\.100)' | wc -l | tr -d ' '; }

echo "runet-direct on $(sw_vers -productName) $(sw_vers -productVersion), $(uname -m); physical gateway: $GW"
BEFORE=$(others)
echo "routes through $GW that belong to other tools: $BEFORE"
"$BIN" --version

# ---------------------------------------------------------------------------------------------
step "A. foreground checks (private data folder, nothing is installed)"
H=$DIR/home-a; rm -rf "$H"; mkdir -p "$H"
export RUNET_DIRECT_HOME=$H
printf '[ru]\nenabled = false\n[ipv6]\nenabled = false\n' > "$H/config.toml"
printf 'direct 203.0.113.0/24\ndirect 198.51.100.7\n' > "$H/manual.list"

"$BIN" apply
via_gw "203.0.113/24" && ok "203.0.113.0/24 installed via the physical gateway" || bad "203.0.113/24 not installed via $GW"
via_gw "198.51.100.7" && ok "198.51.100.7 installed via the physical gateway" || bad "host route missing"
expect "check: test address is direct" "$BIN" check 203.0.113.5
echo "   info: 8.8.8.8 -> $("$BIN" check 8.8.8.8 | tr -s ' ') (depends on whether a VPN is up right now)"
"$BIN" exclude 203.0.113.128/25 >/dev/null
has_route "203.0.113/24" && bad "the whole /24 is still routed after excluding its upper half" || ok "excluded upper half: the /24 was cut"
has_route "203.0.113/25" && ok "the lower half /25 is routed" || bad "lower /25 missing"
"$BIN" remove 203.0.113.128/25 >/dev/null
has_route "203.0.113/24" && ok "after remove the whole /24 is routed again" || bad "/24 not restored"
"$BIN" status; echo "(status exit code $?)"

"$BIN" pause >/dev/null
has_route "203.0.113/24" && bad "route still there while paused" || ok "paused: our routes removed"
"$BIN" resume >/dev/null
expect "resumed: direct again" "$BIN" check 203.0.113.5

echo; echo "-- daemon: delete a route behind its back, it must come back via route-monitor events"
"$BIN" run >"$DIR/daemon-a.log" 2>&1 &
DPID=$!
sleep 3
kill -0 $DPID 2>/dev/null && ok "daemon is running" || bad "daemon exited: $(cat "$DIR/daemon-a.log")"
/sbin/route -n -q delete -host 198.51.100.7 >/dev/null 2>&1
via_gw "198.51.100.7" && bad "route was not deleted" || ok "route deleted by hand"
wait_for 20 "daemon restored the deleted route" via_gw "198.51.100.7"
kill $DPID 2>/dev/null; wait $DPID 2>/dev/null
echo "daemon log:"; sed 's/^/   | /' "$DIR/daemon-a.log" | tail -8

"$BIN" clear
has_route "203.0.113/24" && bad "203.0.113/24 left after clear" || ok "clear removed the test routes"
unset RUNET_DIRECT_HOME

# ---------------------------------------------------------------------------------------------
step "B. launchd service lifecycle (real install, but configured to touch only the test addresses)"
CFG="/Library/Application Support/runet-direct"
mkdir -p "$CFG"
printf '[ru]\nenabled = false\n[ipv6]\nenabled = false\n' > "$CFG/config.toml"
printf 'direct 203.0.113.0/24\n' > "$CFG/manual.list"

"$BIN" install
INST=/usr/local/bin/runet-direct
[ -x $INST ] && ok "binary installed" || bad "binary not installed"
[ -f /Library/LaunchDaemons/io.github.iresultman.runet-direct.plist ] && ok "launchd plist written" || bad "no plist"
launchctl print system/io.github.iresultman.runet-direct 2>/dev/null | grep -q "state = running" && ok "launchd reports it running" || bad "launchd does not report running"
via_gw "203.0.113/24" && ok "service installed the route" || bad "service did not install the route"
$INST status >/dev/null 2>&1; [ $? -eq 0 ] && ok "status exit code 0 (healthy)" || { bad "status not healthy"; $INST status; }
$INST stop >/dev/null; sleep 1
$INST status >/dev/null 2>&1; [ $? -eq 3 ] && ok "after stop: status exit code 3" || bad "after stop: unexpected status code"
via_gw "203.0.113/24" && ok "stop leaves routes in place" || bad "stop removed routes"
$INST start >/dev/null; sleep 2
$INST status >/dev/null 2>&1; [ $? -eq 0 ] && ok "after start: healthy again" || bad "not healthy after start"
PID=$(launchctl print system/io.github.iresultman.runet-direct 2>/dev/null | awk '/^[[:space:]]*pid = /{print $3; exit}')
kill -9 "$PID" 2>/dev/null
wait_for 25 "launchd restarted the killed daemon (KeepAlive)" bash -c "launchctl print system/io.github.iresultman.runet-direct 2>/dev/null | grep -q 'state = running'"
$INST disable >/dev/null; $INST enable >/dev/null && ok "disable/enable run without errors"

$INST uninstall --purge
[ -e /Library/LaunchDaemons/io.github.iresultman.runet-direct.plist ] && bad "plist left" || ok "plist removed"
[ -e $INST ] && bad "binary left" || ok "binary removed"
[ -e "$CFG" ] && bad "config folder left (--purge)" || ok "config folder removed"
has_route "203.0.113/24" && bad "test route left after uninstall" || ok "uninstall removed the test route"

# ---------------------------------------------------------------------------------------------
step "result"
AFTER=$(others)
echo "routes through $GW that belong to other tools: before=$BEFORE after=$AFTER"
[ "$BEFORE" = "$AFTER" ] && ok "other tools' routes untouched" || bad "other tools' routes changed ($BEFORE -> $AFTER)"
echo
echo "PASSED: $pass   FAILED: $fail"
[ $fail -eq 0 ]
