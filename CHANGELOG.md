# Changelog

## 1.0.0

First release. From here on, semantic versioning applies to what other programs and users rely on:

- the commands and their flags, the `--json` fields of `status`, `check` and `list`, and the exit codes;
- the keys of `config.toml` and the format of `manual.list`;
- where files live on each system and the names of the service (`runet-direct`), the release files and the install
  scripts.

Anything that breaks one of these needs a new major version; additions do not.

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
  `export`, `run`. `status`, `check` and `list` have `--json`; exit codes are stable.
- Targets can be an address, a network, a site name, a pasted link (`https://site.ru/page`) or a mask (`*.site.ru`);
  `site.ru` and `www.site.ru` always go together.
- `export` prints the list as plain CIDR, WireGuard `AllowedIPs`, OpenVPN routes or an AmneziaVPN site list, for VPN
  software that does the splitting itself; it works on a machine without the service.
- Installers: `.exe` (Windows), `.pkg` (macOS, universal), `.deb` and `.rpm` (Linux, x86_64 and ARM), plus
  `install.sh` / `install.ps1`. Release files have SHA-256 checksums and build-provenance attestations.
