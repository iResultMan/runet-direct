#!/usr/bin/env bash
# End-to-end test on Linux inside a throw-away network namespace (needs root).
# It never touches the host's routing: a fake "wire" (dummy0) and a fake VPN (a real tun
# device with default routes and policy rules, like VPN clients install) live in the namespace,
# for IPv4 and IPv6 alike.
#
#   sudo tests/linux-netns.sh [path/to/runet-direct]
set -euo pipefail

BIN=$(realpath "${1:-target/debug/runet-direct}")
NS=rdtest$$
WORK=$(mktemp -d)
DAEMON_PID=""
export RUNET_DIRECT_HOME="$WORK/home"
mkdir -p "$RUNET_DIRECT_HOME"

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 2; }

cleanup() {
  [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
step() { printf '\n== %s\n' "$*"; }
ok()   { pass=$((pass + 1)); printf '   ok: %s\n' "$*"; }
die()  {
  printf '   FAIL: %s\n' "$*"
  [[ -f "$WORK/daemon.log" ]] && { echo '--- daemon log ---'; cat "$WORK/daemon.log"; }
  exit 1
}
rd()   { ip netns exec "$NS" "$BIN" "$@"; }
nsx()  { ip netns exec "$NS" "$@"; }
expect() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else die "$d  ($*)"; fi; }
expect_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then die "$d  ($*)"; else ok "$d"; fi; }
wait_for() { # wait_for <seconds> <description> <command...>
  local t=$1 d=$2; shift 2
  for ((i = 0; i < t * 5; i++)); do
    if "$@" >/dev/null 2>&1; then ok "$d"; return; fi
    sleep 0.2
  done
  die "$d (timed out after ${t}s)"
}
count4() { nsx ip -4 route show table 900 2>/dev/null | wc -l; }
count6() { nsx ip -6 route show table 900 2>/dev/null | wc -l; }
is4() { [[ $(count4) -eq $1 ]]; }
is6() { [[ $(count6) -eq $1 ]]; }
all_via4() { [[ $(nsx ip -4 route show table 900 | grep -vc "via $1 ") -eq 0 ]]; }
all_via6() { [[ $(nsx ip -6 route show table 900 | grep -vc "via $1 ") -eq 0 ]]; }
has_rule() { nsx ip "-$1" rule show | grep -qE "^$2:.*from all lookup"; } # has_rule 4|6 <priority>
goes() { nsx ip route get "$1" | grep -q "dev $2"; }                       # goes <addr> <dev>

step "namespace with a wire and a VPN (IPv4 and IPv6)"
ip netns add "$NS"
nsx ip link set lo up
nsx ip link add dummy0 type dummy
nsx ip addr add 10.77.0.2/24 dev dummy0
nsx ip addr add fd00:77::2/64 dev dummy0 nodad
nsx ip link set dummy0 up
nsx ip route add default via 10.77.0.1 dev dummy0 metric 100
nsx ip -6 route add default via fd00:77::1 dev dummy0 metric 1024
# The "VPN": a tun device, default routes with a better metric, and a policy rule like the ones
# VPN clients add. Nothing in runet-direct knows these names.
nsx ip tuntap add dev vpnx mode tun
nsx ip addr add 10.8.0.2/24 dev vpnx
nsx ip addr add fd00:88::2/64 dev vpnx nodad
nsx ip link set vpnx up
nsx ip route add default dev vpnx metric 10
nsx ip -6 route add default dev vpnx metric 10
nsx ip route add default dev vpnx table 880
nsx ip -6 route add default dev vpnx table 880
nsx ip rule add priority 30801 from all lookup 880
nsx ip -6 rule add priority 30801 from all lookup 880
ok "namespace $NS ready"
expect_not "before: Russian IPv4 goes into the VPN" goes 5.228.1.1 dummy0
expect_not "before: Russian IPv6 goes into the VPN" goes 2a02:6b8::1 dummy0

step "fake RIPE data served from a file"
cat > "$WORK/ripe.txt" <<'EOF'
2|ripencc|20261002|273655|19821001|20261001|+0000
ripencc|*|ipv4|*|112500224|summary
ripencc|RU|ipv4|5.228.0.0|65536|20110101|assigned|x
ripencc|RU|ipv4|213.59.0.0|65536|20090310|allocated|x
ripencc|RU|ipv4|213.60.0.0|65536|20090310|allocated|x
ripencc|RU|ipv4|37.9.96.0|8192|20100101|allocated|x
ripencc|DE|ipv4|85.214.0.0|65536|20050101|allocated|x
ripencc|RU|ipv6|2a02:6b8::|32|20090310|allocated|x
ripencc|RU|ipv6|2a00:1fa0::|32|20090310|allocated|x
ripencc|DE|ipv6|2a01:238::|32|20090310|allocated|x
EOF
cat > "$RUNET_DIRECT_HOME/config.toml" <<EOF
[ru]
source_url = "file://$WORK/ripe.txt"
min_prefixes = 3
[daemon]
interval_seconds = 20
EOF

step "apply"
rd apply
# `ip rule` prints a label instead of 900 when the host's rt_tables names the table.
expect "IPv4 rule 2500 exists" has_rule 4 2500
expect "IPv6 rule 2500 exists" has_rule 6 2500
# 213.59/16 and 213.60/16 touch but are not /15-aligned, so they stay two blocks.
is4 4 && ok "4 IPv4 blocks installed (foreign lines ignored)" || die "expected 4 IPv4 routes, got $(count4)"
is6 2 && ok "2 IPv6 blocks installed (the prefix length, not an address count, is used)" || die "expected 2 IPv6 routes, got $(count6)"
expect "IPv4 routes use the wire gateway" all_via4 10.77.0.1
expect "IPv6 routes use the wire gateway" all_via6 fd00:77::1
expect "a Russian IPv4 address leaves via the wire" goes 5.228.1.1 dummy0
expect "a Russian IPv6 address leaves via the wire" goes 2a02:6b8::1 dummy0
expect "a foreign IPv4 address still goes into the VPN" goes 8.8.8.8 vpnx
expect "a foreign IPv6 address still goes into the VPN" goes 2606:4700::1111 vpnx
expect "check <russian ipv4> exits 0" rd check 213.59.200.1
expect "check <russian ipv6> exits 0" rd check 2a00:1fa0:5::1
expect_not "check <foreign ipv4> exits 1" rd check 8.8.8.8
expect_not "check <foreign ipv6> exits 1" rd check 2606:4700::1111
expect "second apply is a no-op" bash -c "ip netns exec $NS $BIN apply 2>&1 | grep -c 'added 0, removed 0' | grep -q 2"

step "manual list (both families)"
rd add 1.2.3.4 2001:db8:77::/48 >/dev/null
expect "added IPv4 host is direct" rd check 1.2.3.4
expect "added IPv6 net is direct" rd check 2001:db8:77::9
rd exclude 5.228.1.0/24 2a02:6b8:1::/48 >/dev/null
expect_not "excluded IPv4 slice goes back to the VPN" rd check 5.228.1.9
expect_not "excluded IPv6 slice goes back to the VPN" rd check 2a02:6b8:1::9
expect "rest of the IPv4 block stays direct" rd check 5.228.2.9
expect "rest of the IPv6 block stays direct" rd check 2a02:6b8:2::9
rd remove 5.228.1.0/24 2a02:6b8:1::/48 1.2.3.4 2001:db8:77::/48 >/dev/null
expect "after remove the IPv4 slice is direct again" rd check 5.228.1.9
expect "after remove the IPv6 slice is direct again" rd check 2a02:6b8:1::9
expect_not "after remove the host is back in the VPN" rd check 1.2.3.4

step "each family can be switched off on its own"
rd config set ipv6.enabled false >/dev/null
is6 0 && ok "IPv6 routes removed" || die "IPv6 routes remain: $(count6)"
expect_not "IPv6 rule removed" has_rule 6 2500
is4 4 && ok "IPv4 untouched" || die "IPv4 changed: $(count4)"
expect "IPv4 still direct" rd check 5.228.1.9
expect_not "IPv6 back in the VPN" rd check 2a02:6b8::1
[[ $(rd config get ipv6.enabled) == false ]] && ok "config get reports the change" || die "config get"
grep -q '^\[ipv6\]' "$RUNET_DIRECT_HOME/config.toml" && ok "config.toml keeps its structure" || die "config.toml mangled"
rd config set ipv6.enabled true >/dev/null
is6 2 && ok "IPv6 back after re-enabling" || die "IPv6 not restored: $(count6)"
rd config set ipv4.enabled false >/dev/null
is4 0 && ok "IPv4 routes removed while IPv6 stays" || die "IPv4: $(count4)"
is6 2 && ok "IPv6 untouched" || die "IPv6 changed"
rd config set ipv4.enabled true >/dev/null
is4 4 && ok "IPv4 back" || die "IPv4 not restored"
expect_not "a typo in a setting is refused" rd config set ipv9.enabled true
expect_not "a wrong value type is refused" rd config set ipv4.enabled maybe

step "bulk import, pause and resume"
printf '# a table sent by another program\n203.0.113.0/24\n198.51.100.5\n2001:db8:99::/48\n' > "$WORK/table.txt"
rd add --file "$WORK/table.txt" >/dev/null
expect "IPv4 targets from a file are direct" rd check 203.0.113.77
expect "IPv6 target from the file is direct" rd check 2001:db8:99::1
echo 192.0.2.9 | rd add --file - >/dev/null
expect "targets from stdin are direct" rd check 192.0.2.9
rd remove --file "$WORK/table.txt" >/dev/null
rd remove 192.0.2.9 >/dev/null
expect_not "removed with the same file" rd check 203.0.113.77
rd pause --for 1h >/dev/null
expect_not "paused: Russian IPv4 goes through the VPN" rd check 213.59.200.1
expect_not "paused: Russian IPv6 goes through the VPN" rd check 2a02:6b8::1
{ is4 0 && is6 0; } && ok "paused: no routes installed" || die "paused but routes remain ($(count4)/$(count6))"
out=$(rd status || true); grep -q PAUSED <<<"$out" && ok "status announces the pause" || die "status does not mention the pause"
rd resume >/dev/null
expect "resumed: IPv4 direct again" rd check 213.59.200.1
expect "resumed: IPv6 direct again" rd check 2a02:6b8::1
{ is4 4 && is6 2; } && ok "resumed: 4 + 2 routes back" || die "resumed but $(count4)/$(count6) routes"
rd pause --for 3s >/dev/null
sleep 5
rd apply >/dev/null
expect "a pause with a duration ends by itself" rd check 213.59.200.1

step "bad download never wipes the table"
b4=$(count4); b6=$(count6)
sed -i "s#ripe.txt#missing.txt#" "$RUNET_DIRECT_HOME/config.toml"
rd refresh >/dev/null 2>&1 || true
{ is4 "$b4" && is6 "$b6"; } && ok "tables untouched after a failed download ($b4 + $b6 routes)" || die "table changed"
sed -i "s#missing.txt#ripe.txt#" "$RUNET_DIRECT_HOME/config.toml"
printf 'ripencc|RU|ipv4|9.9.9.0|256|20090310|allocated|x\n' > "$WORK/tiny.txt"
sed -i "s#ripe.txt#tiny.txt#" "$RUNET_DIRECT_HOME/config.toml"
sed -i 's/min_prefixes = 3/min_prefixes = 30/' "$RUNET_DIRECT_HOME/config.toml"
rd refresh >/dev/null 2>&1 || true
{ is4 "$b4" && is6 "$b6"; } && ok "truncated list rejected (below min_prefixes)" || die "truncated list was accepted"
sed -i "s#tiny.txt#ripe.txt#; s/min_prefixes = 30/min_prefixes = 3/" "$RUNET_DIRECT_HOME/config.toml"

step "daemon repairs what the network breaks"
nsx "$BIN" run >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 1.5
kill -0 "$DAEMON_PID" 2>/dev/null && ok "daemon is running" || die "daemon exited: $(cat "$WORK/daemon.log")"

nsx ip rule del priority 2500 from all lookup 900
wait_for 8 "IPv4 rule vanished (tethering) -> restored within seconds, not the 20 s timer" has_rule 4 2500
nsx ip -6 rule del priority 2500 from all lookup 900
wait_for 8 "IPv6 rule vanished -> restored within seconds" has_rule 6 2500

nsx ip route replace default via 10.77.0.9 dev dummy0 metric 100
wait_for 10 "IPv4 gateway changed -> every route re-pointed" all_via4 10.77.0.9
nsx ip -6 route replace default via fd00:77::9 dev dummy0 metric 1024
wait_for 10 "IPv6 gateway changed -> every route re-pointed" all_via6 fd00:77::9
{ is4 4 && is6 2; } && ok "still exactly 4 + 2 routes" || die "route counts are $(count4)/$(count6)"

nsx ip route replace default via 10.77.0.1 dev dummy0 metric 100
nsx ip -6 route replace default via fd00:77::1 dev dummy0 metric 1024
wait_for 10 "IPv4 gateway restored -> routes follow" all_via4 10.77.0.1
wait_for 10 "IPv6 gateway restored -> routes follow" all_via6 fd00:77::1

nsx ip route flush table 900
nsx ip -6 route flush table 900
wait_for 30 "tables wiped externally -> rebuilt by the 20 s safety-net check" bash -c "[[ \$(ip netns exec $NS ip -4 route show table 900 | wc -l) -eq 4 && \$(ip netns exec $NS ip -6 route show table 900 | wc -l) -eq 2 ]]"

rd exclude 213.59.9.0/24 --for 4s >/dev/null
expect_not "temporary exclusion: slice goes through the VPN" rd check 213.59.9.9
wait_for 15 "temporary exclusion reverts by itself (daemon woke at the expiry, not at the 20 s timer)" rd check 213.59.9.9
grep -q '213.59.9.0' "$RUNET_DIRECT_HOME/manual.list" && die "expired entry still in manual.list" || ok "expired entry removed from manual.list"
grep -q "temporary entries expired" "$WORK/daemon.log" && ok "expiry is logged" || die "expiry not logged"

step "VPN independence: another VPN, same behaviour"
nsx ip link del vpnx
nsx ip tuntap add dev wg-other mode tun
nsx ip addr add 10.9.0.2/24 dev wg-other
nsx ip addr add fd00:99::2/64 dev wg-other nodad
nsx ip link set wg-other up
nsx ip route add 0.0.0.0/1 dev wg-other
nsx ip route add 128.0.0.0/1 dev wg-other
nsx ip -6 route add ::/1 dev wg-other
nsx ip -6 route add 8000::/1 dev wg-other
expect "russian IPv4 still direct with a different VPN (0/1 + 128/1 style)" goes 213.59.5.5 dummy0
expect "russian IPv6 still direct with a different VPN" goes 2a02:6b8::1 dummy0
expect_not "other IPv4 traffic is in the new VPN" goes 8.8.8.8 dummy0
expect_not "other IPv6 traffic is in the new VPN" goes 2606:4700::1111 dummy0

step "a VPN that inserts its rule in FRONT of ours (the 'VPN drops to the bottom' worry)"
nsx ip route add default dev wg-other table 880
nsx ip rule add priority 1000 from all lookup 880
wait_for 10 "IPv4: rule at 1000 shadowed ours -> daemon moved ours just above it (999)" has_rule 4 999
expect_not "IPv4: old position removed (no duplicate rule)" has_rule 4 2500
expect "IPv4: russian traffic direct again despite the VPN rule" goes 213.59.5.5 dummy0
expect_not "IPv4: other traffic still goes into the VPN" goes 8.8.8.8 dummy0
nsx ip rule add priority 500 from all lookup 880
wait_for 10 "IPv4: VPN went even lower (500) -> ours follows (499)" has_rule 4 499
expect "IPv4: russian traffic still direct" goes 213.59.5.5 dummy0
nsx ip -6 route add default dev wg-other table 880
nsx ip -6 rule add priority 700 from all lookup 880
wait_for 10 "IPv6: rule at 700 shadowed ours -> moved above it (699)" has_rule 6 699
expect "IPv6: russian traffic direct again" goes 2a02:6b8::1 dummy0
# A diverting rule that is NOT a plain `from all` rule cannot be moved above; it must still be reported.
nsx ip rule add priority 300 not from all fwmark 0x7 lookup 880
wait_for 10 "a fwmark-style diverting rule is reported by the daemon, not ignored" bash -c "grep -q 'not a plain' '$WORK/daemon.log'"
expect_not "check flags the leak while that rule exists" rd check
nsx ip rule del priority 300 not from all fwmark 0x7 lookup 880
wait_for 12 "check is healthy again once the rule is gone" rd check
grep -q "rule moved" "$WORK/daemon.log" && ok "the moves are logged" || die "no log line about the move"
set +e; rd status --json >"$WORK/s2.json"; set -e
python3 -c "
import json
f = {x['family']: x for x in json.load(open('$WORK/s2.json'))['health']['families']}
assert (f['IPv4']['rule_priority'], f['IPv6']['rule_priority']) == (499, 699), (f['IPv4'], f['IPv6'])
" && ok "status --json reports the moved rule priorities (499 / 699) for neighbouring tools" || die "rule_priority missing from status --json"
set +e; rd check >/dev/null 2>&1; c=$?; set -e
[[ $c -eq 0 ]] && ok "check reports healthy after the guard acted" || die "check exit code $c"

step "status"
set +e
rd status --json >"$WORK/status.json"; code=$?
set -e
[[ $code -eq 4 || $code -eq 3 || $code -eq 1 || $code -eq 0 ]] && ok "status exit code is one of the documented ones ($code)" || die "status exit code $code"
python3 -c "
import json
d = json.load(open('$WORK/status.json'))['health']
f = {x['family']: x for x in d['families']}
assert f['IPv4']['wanted'] == 4 and f['IPv4']['missing'] == 0, f['IPv4']
assert f['IPv6']['wanted'] == 2 and f['IPv6']['missing'] == 0, f['IPv6']
" && ok "status --json reports both families complete" || die "status json"

step "clear"
kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null || true; DAEMON_PID=""
rd clear >/dev/null
{ is4 0 && is6 0; } && ok "table 900 empty in both families" || die "tables not empty"
expect_not "IPv4 rule removed wherever the guard had moved it (499)" has_rule 4 499
expect_not "IPv6 rule removed wherever the guard had moved it (699)" has_rule 6 699
expect "the VPN's own rules are left alone" has_rule 4 500
expect_not "russian IPv4 traffic is back in the VPN" goes 5.228.1.1 dummy0
expect_not "russian IPv6 traffic is back in the VPN" goes 2a02:6b8::1 dummy0

printf '\nALL PASSED (%d checks)\n' "$pass"
