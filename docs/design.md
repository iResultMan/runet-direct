# Design notes

Why `runet-direct` works the way it does. Most of this was learned the hard way on a machine where several ad-hoc
scripts fought over the same routing table.

## The one job

Make traffic to Russian address blocks leave through the physical connection, whatever VPN is active, and keep it
that way without anyone watching. It deliberately does nothing else: no per-application rules, no DNS handling, no
tethering/multi-uplink logic. Programs that need to react to network changes (for example a gateway or
channel manager) are separate projects: they watch the same kernel events themselves.

## Data flow

```
RIPE delegated-extended file ──► country blocks (aggregated, cached on disk)
manual.list (direct / vpn, optional expiry) ──► ranges
        (country ∪ direct) − vpn  ──►  wanted route set
                                           │ diff against the OS
                                           ▼
                              add / replace / remove routes
```

Everything is plain address-range arithmetic (`src/cidr.rs`): merge, subtract, re-express as the fewest CIDR
blocks. `exclude` therefore carves a hole out of a larger block instead of removing the whole block, and
`pause` is just `exclude 0.0.0.0/0`.

## Per operating system

| | Mechanism | Why it beats the VPN |
| --- | --- | --- |
| Linux | Private table (default 900) + `ip rule priority 2500 from all lookup 900` | The rule is consulted before the VPN's. Destinations not in the table fall through to the VPN. |
| macOS | Plain routes to the physical gateway, tracked in `state.json` | Longest prefix wins; blocks are far more specific than a VPN's default/`0/1`+`128/1` routes. |
| Windows | Same, via `netsh` scripts; adapters classified with `Get-NetAdapter -Physical` | Same. |

The physical uplink is chosen by *what the interface is* (hardware-backed vs. virtual: `tun_flags`, `/sys/.../device`,
link type on Linux; `-Physical` on Windows; interface family on macOS). VPN names are never matched, apart from a
last-resort name hint for virtual links.

## Rules that were paid for

1. **Judge by the effect, not by presence.** A rule that exists can still lead nowhere: a VPN may place its own
   catch-all rule at a smaller priority number. On Linux, after the routes are in place, the daemon asks the kernel
   where a probe address inside the wanted set would go. If it leaves through a tunnel, ours is re-created just
   above the rule that answered, and the old one removed (add first, then delete, so there is never a gap).
   `clear` removes the rule wherever it ended up. This needs no knowledge of the VPN.
2. **Never flush, never wipe.** Routes are diffed, not rebuilt. A missing country list, a failed download or a
   truncated file (`min_prefixes`) can only add or keep routes, never remove them. A missing uplink leaves the
   routes alone.
3. **`stop` does not remove routes.** A stopped daemon must not silently push Russian traffic back into the VPN.
   `clear` / `uninstall` are explicit.
4. **The table is a number, not a name.** `rt_tables` labels are cosmetic and may be renamed; `ip rule` prints the
   label instead of the number when one exists. Parsing resolves both, and commands always use the number.
5. **Echo suppression must not eat real events.** Our own changes show up in `ip monitor`. The daemon waits for
   quiet after a change but, if anything arrived meanwhile, runs one more (cheap, usually empty) pass instead of
   discarding it. Route lines of our own table are filtered at the source.
6. **Rules owned by others.** If something else must beat this rule, give it a smaller priority number than the
   one in `config.toml`. The shadow guard only ever moves *our* rule, and only above a rule that actually diverts
   the probe into a tunnel.
7. **Locale independence on Windows.** Only JSON from PowerShell and the numeric rows of `route print` are parsed.
8. **Only the daemon (and `refresh`) downloads.** Quick commands such as `add` never wait for the 18 MB file, and each
   process downloads into its own temporary file, so two of them can never mix. While the daemon is downloading it
   does not react to network events; the download takes seconds on a normal link, and the next pass catches up.
9. **A diversion that cannot be fixed is still reported.** If a rule that is not a plain `from all` rule (fwmark,
   `not`, `to` ...) sends the probe into a tunnel, it cannot be moved above automatically, but the daemon logs it
   and `check` / `status` fail instead of staying quiet.
10. **Temporary entries expire by themselves.** Expiry is enforced by the daemon (it wakes at the exact moment), not
   by the caller, so a crashed controller cannot leave a forgotten exclusion behind.

## IPv4 and IPv6

Both families go through the same engine; everything is keyed by family: separate range sets, separate uplinks
(an IPv6 gateway is usually a link-local `fe80::` address), separate rules (`ip -6 rule`), separate ownership in
`state.json`. Each family has an `enabled` switch. A disabled family is not managed at all; routes installed for it
earlier are removed once. A machine without IPv6 is not an error: with no IPv6 uplink, the family is skipped and no
rule is created for it.

RIPE writes the size of an IPv4 block as an address count and the size of an IPv6 block as a prefix length; the parser
handles both. Thresholds against truncated downloads apply per family (`min_prefixes` for IPv4, a tenth of it for IPv6).

## Names, masks and delivery networks

A site name is turned into addresses by the system resolver, every few hours. `site.ru` and `www.site.ru` always
travel together. A mask (`*.site.ru` or `.site.ru`) means the site itself plus the subdomains that real services use
most (`COMMON_LABELS` in `src/sources.rs`): DNS cannot list a domain's subdomains, so anything outside that list has
to be added by its own name.

A mask solves a *naming* problem, not an *addressing* one. A site behind a delivery network resolves to addresses that
rotate and are shared with other sites, and the browser may be told different ones than the daemon sees. Routing by
address can only follow what the daemon resolved.

## Known limits

- A firewall-based VPN kill switch blocks the direct path by design.
- The very first download needs working DNS and a route to RIPE; later runs use the cached list.
- Domains in `manual.list` are resolved through the system resolver, which under a VPN may be the VPN's resolver
  and can return different (geo-dependent) answers.
- On macOS/Windows the table is shared with everything else, so ownership is tracked in `state.json`; a route
  that someone else created for the same prefix and gateway is indistinguishable from ours.

## Migrating from hand-written scripts

Stop whatever else writes the same table or rule (units, NetworkManager dispatcher hooks, cron jobs) before
installing. Two writers to one table produce flapping routes. Anything else that must react to network events
(for example per-interface source rules) should keep its own trigger and use a rule priority with a smaller number
than this program's, so that it is evaluated first.
