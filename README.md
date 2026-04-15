# Ostiarius

> *Latin: doorkeeper / porter* — the Roman slave whose job was to stand at the door, inspect visitors, and decide who enters.

Ostiarius is the **reverse proxy** component of [Limen](https://github.com/getlimen/limen). It terminates public TLS, routes HTTP(S) traffic through WireGuard tunnels to backend services, and enforces resource-level authentication (password / SSO / email allowlist).

## Role in the Limen platform

- **Listens on:** 80 (ACME HTTP-01) + 443 (TLS)
- **Configured by:** Limen via JSON-over-WebSocket (`/api/proxies/ws`)
- **TLS:** Let's Encrypt via [LettuceEncrypt-Archon](https://github.com/Archon-maintainer/LettuceEncrypt-Archon)
- **Routing engine:** [YARP](https://github.com/dotnet/yarp)
- **Auth:** Ed25519-signed JWT verified locally (no round-trip to Limen per request)

## How it's installed

**You don't install Ostiarius directly.** It's brought up automatically by [Limentinus](https://github.com/getlimen/limentinus) on any node with the `proxy` role.

Admin opt-in to proxy role in Limen UI when enrolling a node.

## Tech stack

.NET 10 / NativeAOT • Kestrel + YARP • LettuceEncrypt-Archon • System.Net.WebSockets • NSec.Cryptography (Ed25519)

## Status

In active development. See [`limen/docs/superpowers/plans/2026-04-14-plan-04-ostiarius-proxy.md`](https://github.com/getlimen/limen/blob/main/docs/superpowers/plans/2026-04-14-plan-04-ostiarius-proxy.md).

## Development

Local testing without a full compose stack: set `Ostiarius:LimenUrl` to `ws://localhost:5098` and provide a valid `ProxyNodeId` + `AgentSecret` (obtained by enrolling a Limentinus with `proxy` role against limen first). Then `dotnet run` Ostiarius — it will connect, authenticate, and receive any configured routes.

### Sync contracts from limen

Snapshot checked in at `src/Limen.Contracts/`. Re-sync when upstream changes:

```bash
bash scripts/sync-contracts.sh
```

## License

[Apache 2.0](LICENSE)
