# Roadmap

What is planned, in order. Dates are not promised; the order is.

## 1.1: "Russia through the VPN" (for people who live abroad)

**Why.** The mirror image of today's job. Someone outside Russia wants Russian services (Gosuslugi, banks, the tax
office) to see a Russian address, while everything else (AI services, streaming, ...) should leave directly, not through
a Russian address. Today `runet-direct export` already gives the list for a VPN that does the splitting itself (see the
README); 1.1 makes the service do it automatically and keep it repaired.

**Design sketch.**
- `routing.mode = "direct"` (default, today's behaviour) or `"tunnel"`: in tunnel mode the Russian blocks are routed *into*
  the VPN instead of out through the physical gateway.
- **Choosing the tunnel.** `routing.interface` names it. Without it, pick automatically only when exactly one tunnel
  interface is up after leaving out mesh networks (Tailscale, ZeroTier, NetBird); otherwise refuse and ask.
- **The "uplink" becomes the tunnel itself:** an on-link route (`dev <tunnel>`, no next hop) on Linux, macOS and Windows.
  The VPN must not need a default route, which is the usual setup for this scenario.
- **Invert the checks.** The probe must end up *in* the tunnel; the shadow guard on Linux triggers when it does not.
  `status` and `check` wording and the JSON (`mode`) follow.
- **Manual list keeps its meaning:** `direct` = outside the tunnel, `vpn` = through it. In tunnel mode the Russian blocks
  default to `vpn`, so `add` and `exclude` read the same as before.
- **Switching modes cleans up:** routes of the old mode are removed once, like a disabled address family.
- **Tests:** a network-namespace case with a VPN that has no default route; mode switch; a missing or ambiguous tunnel.
- **Message:** a second page or section on the website for this audience; the name `runet-direct` stays.

**Open questions.** Whether the daemon should warn when the VPN's exit is not Russian (it cannot know); how IPv6 behaves
when the VPN has no IPv6; what to do when the tunnel interface disappears and returns under another name.

## Candidates after that

- **Sites behind delivery networks.** A curated, monthly-refreshed list of Russian services that sit behind foreign
  networks (imported as names, as `add --file` already can); re-resolving names more often and keeping the addresses
  seen over the last day, so that rotating addresses are not lost.
- **A small window or tray icon** for status and pause, for people who do not use a terminal.
- **Code signing:** a free certificate for Windows (SignPath Foundation) to remove the "unknown publisher" warning.

## Decided against

- **Mobile apps** (decided 2026-10-14). Phones allow only one VPN, so the service cannot work beside another VPN there;
  an own VPN client is a different, much larger product. `export` covers phone VPN apps that accept a list.
- **Managing DNS.** The user's DNS is not this program's zone.
