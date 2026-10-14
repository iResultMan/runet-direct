# Security policy

runet-direct runs as root / SYSTEM and changes the routing table, so security reports are taken seriously.

**Please do not open a public issue for a vulnerability.** Use GitHub's
[private vulnerability reporting](https://github.com/iResultMan/runet-direct/security/advisories/new) or write to
i.result.man@gmail.com. Expect a first answer within a few days.

What is in scope: anything that lets an unprivileged user or a remote party make the service change routes, run
commands or write files it should not; problems with the installers or the release files (checksums, attestations); the
install scripts.

What the program does on the network: once a month it downloads one file from `ftp.ripe.net`, through the system
`curl`. It listens on no port, sends no telemetry and runs no code from the downloaded file.

Release files carry a SHA-256 checksum and a build-provenance attestation; verify with
`gh attestation verify <file> --repo iResultMan/runet-direct`.
