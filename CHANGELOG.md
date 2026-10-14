# Changelog

## 0.1.0

First release.

- Background service for Linux (systemd), macOS (launchd) and Windows (Task Scheduler) that sends Russian address
  blocks out through the physical connection while everything else keeps using the VPN. No knowledge of the VPN is
  needed; the uplink is chosen by what an interface is.
- IPv4 and IPv6, each switchable on its own.
- Linux: the routing rule is judged by its effect and moved above any VPN rule that shadows it; a diversion that cannot
  be fixed is reported instead of ignored.
- Routes repair themselves within seconds of a network change; replacements are added before stale routes are removed.
- A failed or truncated download never touches the routes in place.
- Commands: `install`, `uninstall`, `start`, `stop`, `restart`, `enable`, `disable`, `status`, `check`, `apply`,
  `refresh`, `clear`, `add`, `exclude` (`--for`, `--until`, `--file`), `remove`, `list`, `pause`, `resume`, `config`,
  `run`. `status`, `check` and `list` have `--json`; exit codes are stable.
- Installers: `.exe` (Windows), `.pkg` (macOS, universal), `.deb` and `.rpm` (Linux, x86_64 and ARM), plus
  `install.sh` / `install.ps1`. Release files have SHA-256 checksums and build-provenance attestations.
