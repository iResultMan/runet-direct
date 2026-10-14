#!/usr/bin/env bash
# End-to-end test on Linux inside a throw-away network namespace (needs root).
# It never touches the host's routing: a fake "wire" (dummy0) and a fake VPN (a real tun
# device with a default route and a policy rule, like VPN clients install) live in the namespace.
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
expect() { # expect "<description>" <command...>
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then ok "$d"; else die "$d  ($*)"; fi
}
expect_not() {
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then die "$d  ($*)"; else ok "$d"; fi
}
wait_for() { # wait_for <seconds> <description> <command...>
  local t=$1 d=$2; shift 2
  for ((i = 0; i < t * 5; i++)); do
    if "$@" >/dev/null 2>&1; then ok "$d"; return; fi
    sleep 0.2
  done
  die "$d (timed out after ${t}s)"
}
table_count() { nsx ip -4 route show table 900 | wc -l; }
all_via() { [[ $(nsx ip -4 route show table 900 | grep -vc "via $1 ") -eq 0 ]]; }

step "namespace with a wire and a VPN"
ip netns add "$NS"
nsx ip link set lo up
nsx ip link add dummy0 type dummy
nsx ip addr add 10.77.0.2/24 dev dummy0
nsx ip link set dummy0 up
nsx ip route add default via 10.77.0.1 dev dummy0 metric 100
# The "VPN": a tun device, a default route in main with a better metric, and a policy
# rule like the ones VPN clients add. Nothing in runet-direct knows these names.
nsx ip tuntap add dev vpnx mode tun
nsx ip addr add 10.8.0.2/24 dev vpnx
nsx ip link set vpnx up
nsx ip route add default dev vpnx metric 10
nsx ip route add default dev vpnx table 880
nsx ip rule add priority 30801 from all lookup 880
ok "namespace $NS ready"
expect_not "before: Russian traffic goes into the VPN" bash -c "ip netns exec $NS ip route get 5.228.1.1 | grep -q dummy0"

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
expect "rule 2500 -> table 900 exists" bash -c "ip netns exec $NS ip -4 rule show | grep -qE '^2500:.*from all lookup (900|[a-z_]+)'"
# 213.59/16 and 213.60/16 touch but are not /15-aligned, so they stay two blocks; the IPv6,
# DE and summary lines must be ignored.
[[ $(table_count) -eq 4 ]] && ok "4 blocks installed (IPv6/foreign/summary lines ignored)" || die "expected 4 routes, got $(table_count)"
expect "all routes use the wire gateway, not the VPN" all_via 10.77.0.1
expect "a Russian address now leaves via the wire" bash -c "ip netns exec $NS ip route get 5.228.1.1 | grep -q 'dev dummy0'"
expect "a foreign address still goes into the VPN" bash -c "ip netns exec $NS ip route get 8.8.8.8 | grep -q 'dev vpnx'"
expect "check <russian ip> exits 0" rd check 213.59.200.1
expect_not "check <foreign ip> exits 1" rd check 8.8.8.8
expect "second apply is a no-op" bash -c "ip netns exec $NS $BIN apply 2>&1 | grep -q 'added 0, removed 0'"

step "manual list"
rd add 1.2.3.4 >/dev/null
expect "added host is direct" rd check 1.2.3.4
rd exclude 5.228.1.0/24 >/dev/null
expect_not "excluded slice goes back to the VPN" rd check 5.228.1.9
expect "rest of the block stays direct" rd check 5.228.2.9
expect "rest of the block (below the hole) stays direct" rd check 5.228.0.9
rd remove 5.228.1.0/24 1.2.3.4 >/dev/null
expect "after remove the slice is direct again" rd check 5.228.1.9
expect_not "after remove the host is back in the VPN" rd check 1.2.3.4

step "bulk import, pause and resume"
printf '# a table sent by another program\n203.0.113.0/24\n198.51.100.5\n' > "$WORK/table.txt"
rd add --file "$WORK/table.txt" >/dev/null
expect "targets from a file are direct" rd check 203.0.113.77
expect "second target from the file is direct" rd check 198.51.100.5
echo 192.0.2.9 | rd add --file - >/dev/null
expect "targets from stdin are direct" rd check 192.0.2.9
rd remove --file "$WORK/table.txt" >/dev/null
rd remove 192.0.2.9 >/dev/null
expect_not "removed with the same file" rd check 203.0.113.77
rd pause --for 1h >/dev/null
expect_not "paused: russian address goes through the VPN" rd check 213.59.200.1
[[ $(table_count) -eq 0 ]] && ok "paused: no routes installed" || die "paused but $(table_count) routes remain"
out=$(rd status || true); grep -q PAUSED <<<"$out" && ok "status announces the pause" || die "status does not mention the pause"
rd resume >/dev/null
expect "resumed: russian address is direct again" rd check 213.59.200.1
[[ $(table_count) -eq 4 ]] && ok "resumed: 4 routes back" || die "resumed but $(table_count) routes"
rd pause --for 3s >/dev/null
sleep 5
rd apply >/dev/null
expect "a pause with a duration ends by itself" rd check 213.59.200.1

step "bad download never wipes the table"
before=$(table_count)
sed -i "s#ripe.txt#missing.txt#" "$RUNET_DIRECT_HOME/config.toml"
rd refresh >/dev/null 2>&1 || true
[[ $(table_count) -eq $before ]] && ok "table untouched after a failed download ($before routes)" || die "table changed"
sed -i "s#missing.txt#ripe.txt#" "$RUNET_DIRECT_HOME/config.toml"
printf 'ripencc|RU|ipv4|9.9.9.0|256|20090310|allocated|x\n' > "$WORK/tiny.txt"
sed -i "s#ripe.txt#tiny.txt#" "$RUNET_DIRECT_HOME/config.toml"
rd refresh >/dev/null 2>&1 || true
[[ $(table_count) -eq $before ]] && ok "truncated list rejected (below min_prefixes)" || die "truncated list was accepted"
sed -i "s#tiny.txt#ripe.txt#" "$RUNET_DIRECT_HOME/config.toml"

step "daemon repairs what the network breaks"
nsx "$BIN" run >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 1.5
kill -0 "$DAEMON_PID" 2>/dev/null && ok "daemon is running" || die "daemon exited: $(cat "$WORK/daemon.log")"

nsx ip rule del priority 2500 from all lookup 900
wait_for 8 "rule vanished (tethering) -> restored by the daemon within seconds, not the 20 s timer" \
  bash -c "ip netns exec $NS ip -4 rule show | grep -q '^2500:'"

nsx ip route replace default via 10.77.0.9 dev dummy0 metric 100
wait_for 10 "gateway changed -> every route re-pointed to 10.77.0.9" all_via 10.77.0.9
[[ $(table_count) -eq 4 ]] && ok "still exactly 4 routes" || die "route count is $(table_count)"

nsx ip route replace default via 10.77.0.1 dev dummy0 metric 100
wait_for 10 "gateway restored -> routes follow" all_via 10.77.0.1

nsx ip route flush table 900
wait_for 30 "table wiped externally -> rebuilt by the 20 s safety-net check" bash -c "[[ \$(ip netns exec $NS ip -4 route show table 900 | wc -l) -eq 4 ]]"

rd exclude 213.59.9.0/24 --for 4s >/dev/null
expect_not "temporary exclusion: slice goes through the VPN" rd check 213.59.9.9
wait_for 15 "temporary exclusion reverts by itself (daemon woke at the expiry, not at the 20 s timer)" rd check 213.59.9.9
grep -q '213.59.9.0' "$RUNET_DIRECT_HOME/manual.list" && die "expired entry still in manual.list" || ok "expired entry removed from manual.list"
grep -q "temporary entries expired" "$WORK/daemon.log" && ok "expiry is logged" || die "expiry not logged"

step "VPN independence: another VPN, same behaviour"
nsx ip link del vpnx
nsx ip tuntap add dev wg-other mode tun
nsx ip addr add 10.9.0.2/24 dev wg-other
nsx ip link set wg-other up
nsx ip route add 0.0.0.0/1 dev wg-other
nsx ip route add 128.0.0.0/1 dev wg-other
expect "russian traffic still direct with a different VPN (0/1 + 128/1 style)" bash -c "ip netns exec $NS ip route get 213.59.5.5 | grep -q 'dev dummy0'"
expect_not "other traffic is in the new VPN" bash -c "ip netns exec $NS ip route get 8.8.8.8 | grep -q 'dev dummy0'"

step "a VPN that inserts its rule in FRONT of ours (the 'VPN drops to the bottom' worry)"
nsx ip route add default dev wg-other table 880
nsx ip rule add priority 1000 from all lookup 880
wait_for 10 "rule at 1000 shadowed ours -> daemon moved ours just above it (999)" bash -c "ip netns exec $NS ip -4 rule show | grep -qE '^999:.*from all lookup'"
expect_not "old position removed (no duplicate rule)" bash -c "ip netns exec $NS ip -4 rule show | grep -q '^2500:'"
expect "russian traffic direct again despite the VPN rule" bash -c "ip netns exec $NS ip route get 213.59.5.5 | grep -q 'dev dummy0'"
expect_not "other traffic still goes into the VPN" bash -c "ip netns exec $NS ip route get 8.8.8.8 | grep -q 'dev dummy0'"
nsx ip rule add priority 500 from all lookup 880
wait_for 10 "VPN went even lower (500) -> ours follows (499)" bash -c "ip netns exec $NS ip -4 rule show | grep -qE '^499:.*from all lookup'"
expect "russian traffic still direct" bash -c "ip netns exec $NS ip route get 213.59.5.5 | grep -q 'dev dummy0'"
grep -q "rule moved" "$WORK/daemon.log" && ok "the move is logged" || die "no log line about the move"
# status must stay healthy: the guard repairs it, it is not a lasting problem
set +e; rd check >/dev/null 2>&1; c=$?; set -e
[[ $c -eq 0 ]] && ok "check reports healthy after the guard acted" || die "check exit code $c"

step "status"
set +e
rd status --json >"$WORK/status.json"; code=$?
set -e
[[ $code -eq 4 || $code -eq 3 || $code -eq 1 || $code -eq 0 ]] && ok "status exit code is one of the documented ones ($code)" || die "status exit code $code"
python3 -c "import json,sys; d=json.load(open('$WORK/status.json')); assert d['health']['wanted']==4 and d['health']['missing']==0, d['health']" && ok "status --json reports 4/4 routes" || die "status json"

step "clear"
kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null || true; DAEMON_PID=""
rd clear >/dev/null
[[ $(table_count) -eq 0 ]] && ok "table 900 empty" || die "table not empty"
expect_not "our rule is removed wherever the guard had moved it (499)" bash -c "ip netns exec $NS ip -4 rule show | grep -q '^499:'"
expect "the VPN's own rules are left alone" bash -c "ip netns exec $NS ip -4 rule show | grep -q '^500:'"
expect_not "russian traffic is back in the VPN" bash -c "ip netns exec $NS ip route get 5.228.1.1 | grep -q 'dev dummy0'"

printf '\nALL PASSED (%d checks)\n' "$pass"
