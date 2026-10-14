<p align="center">
  <img src="docs/site/favicon.svg" width="72" alt="">
</p>

<h1 align="center">runet-direct</h1>

<p align="center">
  <b>Keep your VPN on all the time. Russian sites go straight out, everything else goes through the VPN.<br>Install once, forget it.</b>
</p>

<p align="center">
  <a href="https://github.com/iResultMan/runet-direct/actions/workflows/ci.yml"><img src="https://github.com/iResultMan/runet-direct/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/iResultMan/runet-direct/releases/latest"><img src="https://img.shields.io/github/v/release/iResultMan/runet-direct?color=ff5b1f" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-supported-lightgrey" alt="Windows, macOS, Linux">
</p>

<p align="center">
  <a href="https://iresultman.github.io/runet-direct/en/">Website</a> ·
  <a href="https://github.com/iResultMan/runet-direct/releases/latest">Download</a> ·
  <a href="README.ru.md">Русская версия</a>
</p>

---

## The problem

A VPN sends *everything* through its tunnel, including Russian banks, Gosuslugi, marketplaces and mail. Many of them
refuse foreign addresses, ask for extra verification, or just load slowly. So you switch the VPN off for them, then on
again for everything else, and you keep having to remember which state it is in right now. Per-app split tunneling does
not help when one browser opens both worlds.

**With runet-direct you switch nothing.** The VPN stays on all the time: foreign sites go through it, Russian sites open
directly, by themselves.

## What runet-direct does

```
                    ┌── Russian address ─────────────────────────► banks, Gosuslugi, mail   (direct)
 your computer ─────┤
                    └── anything else ───► [ VPN tunnel ] ───────► the rest of the world
```

It is a small background service. It knows which address blocks belong to Russia (from the public RIPE NCC
registry), sends exactly those out through your normal connection, and leaves everything else to your VPN. It does not
care which VPN you use, because it never looks at it. It checks the *result*: where a Russian address would really go.

- **Works with any VPN.** Linux, macOS and Windows. IPv4 and IPv6, each switchable on its own.
- **Repairs itself.** Tethering from a phone, a new network, a VPN that reshuffles its rules: the routes come back
  within seconds. A VPN that puts its rule *in front* of ours is detected, and ours moves above it.
- **One small file.** 1.4 MB, no runtime, no dependencies to install. No telemetry, no account.
- **Scriptable.** Every command has `--json` and stable exit codes, so other programs can drive it.

## Install

| System | Do this |
| --- | --- |
| **Windows 10/11** | Download [`runet-direct-setup-x86_64.exe`](https://github.com/iResultMan/runet-direct/releases/latest/download/runet-direct-setup-x86_64.exe), run it, click *Install*. |
| **macOS 11+** | Download [`runet-direct-macos.pkg`](https://github.com/iResultMan/runet-direct/releases/latest/download/runet-direct-macos.pkg) (Intel and Apple Silicon), open it, click *Continue* and *Install*. |
| **Ubuntu / Debian / Mint** | Download [`runet-direct-linux-amd64.deb`](https://github.com/iResultMan/runet-direct/releases/latest/download/runet-direct-linux-amd64.deb) and double-click it (or `sudo apt install ./file.deb`). |
| **Fedora and other RPM systems** | [`runet-direct-linux-x86_64.rpm`](https://github.com/iResultMan/runet-direct/releases/latest/download/runet-direct-linux-x86_64.rpm): `sudo dnf install ./file.rpm`. |
| **Any Linux or macOS, one line** | `curl -fsSL https://raw.githubusercontent.com/iResultMan/runet-direct/main/install.sh \| sudo sh` |
| **Windows, one line** (elevated PowerShell) | `irm https://raw.githubusercontent.com/iResultMan/runet-direct/main/install.ps1 \| iex` |

ARM builds (`arm64`, `aarch64`) are on the [releases page](https://github.com/iResultMan/runet-direct/releases/latest).
Nothing needs configuring. The first start downloads the address list (about 18 MB) once.

> **A note on warnings.** The installers are not signed with a paid certificate (this is a free project). Windows may
> show *Unknown publisher*: click *More info*, then *Run anyway*. macOS may say it cannot verify the developer:
> right-click the file, choose *Open*. Every release file has a SHA-256 checksum and a build-provenance attestation
> (`gh attestation verify <file> --repo iResultMan/runet-direct`), so you can check what you downloaded.

A minute later:

```
$ runet-direct status
Service:  running (systemd), starts at boot
Tunnels:  tun0 (left alone)
IPv4 uplink: 192.168.1.1 via enp3s0f0
IPv4 routes: 8740 of 8740 in place
IPv6 uplink: none (no IPv6 here)
Country:  8662 IPv4 + 2168 IPv6 blocks, RIPE snapshot 2026-10-13, fetched 0 days ago
Health:   OK
```

`Health: OK` is all you need to see.

## How it compares

| | Split tunneling in your VPN app | Hand-written route scripts | **runet-direct** |
| --- | --- | --- | --- |
| Works with whichever VPN you have | only if the app offers it | tied to one setup | **yes** |
| Knows the Russian address blocks | you maintain a list | you maintain it | **yes, updated monthly** |
| Survives network changes | n/a | only if you wrote that part | **yes, within seconds** |
| Notices when a VPN steals the traffic | n/a | no | **yes** |
| Windows, macOS and Linux | n/a | one system | **all three** |
| Pause with a timer | no | no | **`pause --for 1h`** |

## Everyday commands

Everything except `status`, `check`, `list` and `config` needs root / Administrator.

| Command | What it does |
| --- | --- |
| `status [--json]` | Service and routing state. Exit code: `0` healthy, `1` running but a problem was found, `3` installed but not running, `4` not installed. |
| `check [--json]` | Verify the *real* routing state (asks the OS where sample destinations would go). Exit `0` ok, `1` problem. |
| `check TARGET` | Where would this IP, CIDR or domain go? Prints `direct via <interface>` or `TUNNEL`. Exit `0` direct, `1` tunnel. |
| `pause [--for 1h]` / `resume` | Send **everything** through the VPN for a while, e.g. to test a site as a foreigner would see it. |
| `add TARGET...` | Always go direct: a link pasted from the browser (`https://site.ru/page`), a domain, an IP, `a.b.c.d/n` or an IPv6 prefix. `--file FILE` (or `-` for stdin) takes a whole list. |
| `exclude TARGET...` | Never go direct, even if the Russian list contains it. Takes the same kinds of target, links included. `--for 30m` / `--until <time>` makes it temporary and self-reverting. |
| `remove TARGET...` / `list [--json]` | Edit / show the manual list. |
| `config get KEY` / `config set KEY VALUE` | Read or change one setting, e.g. `config set ipv6.enabled false`. Comments in the file are kept. |
| `install` / `uninstall [--purge]` | Install the service and enable it at boot / remove it **and every route it added**. |
| `start` / `stop` / `restart` / `enable` / `disable` | Control the service. **`stop` leaves the routes in place** so Russian traffic never silently falls back into the VPN. |
| `apply` / `refresh` / `clear` | One-shot sync / download the list now / remove all routes. |

`runet-direct --help` lists everything. Other programs should rely on `--json` and the exit codes, not on the text.

## Settings

Created on install with every option commented. Edit, then `runet-direct restart` (or use `config set`).

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

`config.toml`: `[ipv4]` / `[ipv6]` `enabled`; `[routing]` `table`, `priority`, `interface`, `ignore_interfaces`; `[ru]`
`enabled`, `country`, `source_url`, `refresh_days`, `min_prefixes`; `[daemon]` `interval_seconds`. A disabled address
family is left completely alone (routes added for it earlier are removed once).

## Honest limits

- A VPN **kill switch** built as a firewall rule blocks direct traffic by design, so it defeats this tool.
- The very first download needs a working internet connection. Afterwards the service runs from its saved copy and
  refreshes it monthly; a failed or truncated download never touches the routes in place.
- The list is built from Russian address blocks. A site hosted behind a foreign delivery network is not in it; add it
  with `runet-direct add site.ru`.
- Linux is covered by end-to-end tests (network namespace, a real systemd service, the `.deb` in a container).
  macOS and Windows share the engine and are installed and checked by CI on real machines, but have seen less
  real-world use. Reports are welcome.
- `curl` must be on the path (it ships with Windows 10+, macOS and almost every Linux).

## How it works, in short

- **Linux:** a private routing table plus one rule, "look in my table first", with a smaller priority number than any
  VPN rule. After the routes are in, the service asks the kernel where a Russian address really goes; if a VPN rule
  captures it, ours is moved just above that rule.
- **macOS and Windows:** plain routes to the physical gateway; the most specific route wins, and Russian blocks are far
  more specific than a VPN's catch-all routes.
- The physical connection is chosen by what an interface *is* (hardware vs. virtual), never by a VPN name.

The reasons behind every odd-looking rule are in [docs/design.md](docs/design.md).

## Build and test

```bash
cargo build --release                                   # one static binary
cargo test                                              # unit tests, any OS
sudo tests/linux-netns.sh target/debug/runet-direct     # routing end-to-end in a throw-away network namespace
```

See [CONTRIBUTING.md](CONTRIBUTING.md). `tests/linux-service.sh` and `tests/macos-live.sh` install real services and are
meant for disposable machines.

## Data source and license

Address blocks come from the RIPE NCC delegation statistics
(`ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest`), used under RIPE's terms for raw data.
Code: [MIT](LICENSE). The website uses the Onest typeface under the SIL Open Font License.
