# Contributing

Thanks for looking at runet-direct. The project is deliberately small: one job (send Russian address blocks out
directly, whatever VPN is active) and nothing else. Changes that keep it that way are the easiest to accept.

## Build and check

```bash
cargo build                  # needs Rust 1.89+
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Routing behaviour is tested for real on Linux, inside a throw-away network namespace that never touches your routes:

```bash
sudo tests/linux-netns.sh target/debug/runet-direct
```

`tests/linux-service.sh` installs the real systemd service and `tests/macos-live.sh` the real launchd service. Run them
only on a disposable machine (they refuse to run without `RUNET_TEST_DISPOSABLE=1` / a `sudo` prompt).

The type checker covers every platform from one machine:

```bash
rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin
cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings
```

## Ground rules

- **Judge by the effect.** Whether a route or rule *exists* proves little; ask the OS where traffic really goes.
- **Never wipe.** Routes are diffed, not rebuilt. A failed or truncated download must not remove anything.
- **Parsers are plain functions over text**, compiled and unit-tested on every OS. Add a fixture from real command
  output when you fix a parsing bug (replace personal addresses by documentation ones).
- Keep `README.md` and `README.ru.md` in step, and put reasons for non-obvious behaviour in `docs/design.md`.
- Commit messages in English, imperative mood, with the reason in the body.

## Reporting a problem

Open an issue and attach the output of `runet-direct status --json` and the VPN you use. For a routing problem the output
of `runet-direct check <address>` for the address that misbehaves is the most useful single line.
