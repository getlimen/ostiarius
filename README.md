# Ostiarius

> *Latin: "doorkeeper"* — the person who stands at the door, decides who enters, and announces visitors.

**Ostiarius** is the public-facing reverse proxy component of [Limen](https://github.com/getlimen/limen). It terminates TLS, routes traffic via YARP, and enforces per-route authentication (Ed25519 JWT verification, revocation polling).

## Not installed directly

Ostiarius is automatically deployed by [Limentinus](https://github.com/getlimen/limentinus) on nodes with the `proxy` role. You don't need to manage it manually.

## Features

- **YARP-based reverse proxy** — hostname routing from Limen config
- **Automatic TLS** via LettuceEncrypt-Archon (ACME/Let's Encrypt)
- **Resource authentication** — Ed25519 JWT verify + revocation cache; password, magic-link, SSO flows
- **Identity headers** — injects `X-Limen-User-*` headers to upstream services
- **Config via WebSocket** — auto-reconnecting control channel to Limen

## Tech stack

.NET 10 / ASP.NET Core • NativeAOT • YARP • NSec.Cryptography (Ed25519)

## Architecture

See the [Limen design spec](https://github.com/getlimen/limen/blob/main/docs/superpowers/specs/2026-04-14-limen-design.md).

## License

[Apache 2.0](LICENSE)
