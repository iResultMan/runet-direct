# runet-direct

**Keep Russian-internet traffic off your VPN. Install once, forget it.**

[Русская версия](README.ru.md)

When a VPN is on, *everything* goes through it, including Russian banks, government portals, marketplaces and
mail, many of which refuse foreign addresses or are simply slower that way. `runet-direct` is a small background
service that sends traffic for Russian address blocks straight out through your normal connection while everything
else keeps using the VPN. It works with any VPN, because it never looks at which one you use.

- One static binary, no runtime. Linux, macOS and Windows. IPv4 and IPv6, each switchable on its own.
- Installs itself as a native background service and repairs its own routes when the network changes.
- Controlled from the command line, with JSON output and stable exit codes, so other programs can drive it.

## Install

**Linux / macOS** (needs `curl`; Linux also needs `ip` from iproute2 and systemd for the service):

```bash
curl -fsSL https://raw.githubusercontent.com/iResultMan/runet-direct/main/install.sh | sudo sh
```

**Windows** (PowerShell opened *as Administrator*):

```powershell
irm https://raw.githubusercontent.com/iResultMan/runet-direct/main/install.ps1 | iex
```

**From source** (Rust 1.89+): `cargo build --release`, then `sudo ./target/release/runet-direct install`
(on Windows run `runet-direct.exe install` from an elevated prompt).

The installer downloads one file, verifies its SHA-256, registers the service, starts it and waits for the first
sync (it downloads about 18 MB of public RIPE address data once). After that:

```bash
runet-direct status
```

Re-running `install` upgrades in place and keeps your settings.

## What you will see

```
Service:  running (systemd), starts at boot
Tunnels:  tun0 (left alone)
IPv4 uplink: 192.168.1.1 via enp3s0f0
IPv4 routes: 8662 of 8662 in place
IPv6 uplink: fe80::1 via enp3s0f0
IPv6 routes: 1943 of 1943 in place
Country:  8662 IPv4 + 1943 IPv6 blocks, RIPE snapshot 2026-10-13, fetched 2 days ago
Health:   OK
```

## Commands

Everything except `status`, `check`, `list` and `config` needs root / Administrator.

| Command | What it does |
| --- | --- |
| `install [--no-start]` | Install the service, enable it at boot, start it. Safe to repeat (upgrade). |
| `uninstall [--purge]` | Stop and remove the service **and every route it added**. `--purge` also deletes settings and data. |
| `start` / `stop` / `restart` | Control the service. **`stop` leaves the routes in place** so Russian traffic never silently falls back into the VPN. |
| `enable` / `disable` | Start at boot / do not start at boot. |
| `status [--json]` | Service and routing state. Exit code: `0` healthy, `1` running but a problem was found, `3` installed but not running, `4` not installed. |
| `check [--json]` | Verify the *real* routing state (asks the OS where sample destinations would go). Exit `0` ok, `1` problem. |
| `check TARGET` | Where would this IP, CIDR or domain go? Prints `direct via <interface>` or `TUNNEL`. Exit `0` direct, `1` tunnel. |
| `apply` | Bring the routes to the wanted state once, without the daemon. |
| `refresh` | Download the address list now, then apply. |
| `clear` | Remove all routes and the rule it installed. |
| `add TARGET...` | Always go direct: an IP, `a.b.c.d/n`, or a domain name. |
| `exclude TARGET...` | Never go direct, even if the Russian list contains it. Wins over everything. |
| `remove TARGET...` / `list [--json]` | Edit / show the manual list. |
| `pause [--for 1h]` / `resume` | Send **everything** through the VPN for a while (or until `resume`), e.g. to test how a service behaves from a foreign address. |

`add`, `exclude` and `remove` accept `--file FILE` (one target per line, `-` for standard input), so another program
can hand over a whole table. `add` and `exclude` accept `--for 30m` / `--until 2026-10-14T18:00:00Z`: the entry
then expires by itself, even if the program that created it has crashed, and the service wakes up at that moment.
`status` shows an active pause.
| `config` / `config path` | Show the effective settings / where the files live. |
| `config get KEY` / `config set KEY VALUE` | Read or change one setting such as `ipv6.enabled`; comments in the file are kept, the change is validated and applied at once. |
| `run [--log-file F]` | Run the daemon in the foreground (this is what the service executes). |

Other programs should rely on `--json` output and exit codes, not on the human-readable text.

## Settings

Files are created on install with every option commented. Edit, then `runet-direct restart`.

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Settings, `manual.list` | `/etc/runet-direct/` | `/Library/Application Support/runet-direct/` | `%ProgramData%\runet-direct\` |
| Downloaded data, state | `/var/lib/runet-direct/` | (same as settings) | (same as settings) |
| Log | `journalctl -u runet-direct` | `/var/log/runet-direct.log` | `%ProgramData%\runet-direct\runet-direct.log` |

`manual.list` holds your own entries, one per line (`direct` is the default word):

```
direct 203.0.113.0/24     # always direct
direct bank.example.com   # domains are re-resolved every few hours
vpn    198.51.100.7       # never direct, even though a Russian block contains it
```

`config.toml` options: `[ipv4]` / `[ipv6]` `enabled`; `[routing]` `table`, `priority`, `interface`,
`ignore_interfaces`; `[ru]` `enabled`, `country`, `source_url`, `refresh_days`, `min_prefixes`; `[daemon]`
`interval_seconds`.

**IPv4 and IPv6 are independent.** `runet-direct config set ipv6.enabled false` leaves IPv6 completely alone (and
removes any IPv6 routes this program added earlier); the same switch exists for `ipv4`. A machine that has no
IPv6 connection at all simply has nothing to do for it and stays healthy.

## Does it really work with my VPN?

It does not need to know your VPN. How, in plain words:

- **Linux** keeps its routes in a private table and adds one rule, "look in my table first". A VPN can put a rule of
  its own in front of that. So the service does not trust the rule's presence; it asks the system where a Russian
  address would really go. If the answer is "into the VPN", it moves its rule above whatever intercepts it, and logs
  it. This is checked on every network event.
- **macOS and Windows** have no rules: the most specific route always wins, and the Russian blocks are far more
  specific than the VPN's catch-all routes, so they win by themselves.
- The physical connection is picked by what the interface is (real hardware vs. virtual), never by a VPN name.

Caveat: a VPN "kill switch" implemented as a firewall blocks direct traffic by design, so it defeats this tool.

## Requirements and limits

- `curl` on the path (present on current Windows 10+, macOS and almost every Linux).
- The first download needs a working internet connection. Afterwards the service runs from its saved copy of the
  list and refreshes it monthly; a failed or truncated download never touches the routes in place.
- Windows runs the service as a scheduled task started at boot as SYSTEM (restarted if it exits with an error);
  macOS uses launchd; Linux uses systemd. Other init systems: run `runet-direct run` yourself.
- Linux is covered by end-to-end tests (network namespace, real systemd service). macOS and Windows share the
  engine and are smoke-tested in CI on real runners, but have seen less real-world use.

## Development

```bash
cargo test                                          # unit tests, any OS
cargo build && sudo tests/linux-netns.sh target/debug/runet-direct   # routing e2e in a throw-away namespace
```

`tests/linux-service.sh` installs the real service and is meant for disposable machines only
(`RUNET_TEST_DISPOSABLE=1`). Design notes and the reasons behind the odd-looking rules are in
[docs/design.md](docs/design.md).

## Data source and license

Address blocks come from the RIPE NCC delegation statistics
(`ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest`), used under RIPE's terms for raw data.
Code: [MIT](LICENSE).
