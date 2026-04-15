# CLAUDE.md — ostiarius (reverse proxy)

> **Project**: Ostiarius — component of [Limen](https://github.com/getlimen/limen)
> **Role**: Public-facing reverse proxy with automatic TLS. Runs on `proxy`-role nodes. Receives route config from Limen via WebSocket. Authenticates requests to protected routes locally (Ed25519 JWT verify) — no round-trip to Limen per request.

**For full project context, read [`limen/docs/HANDOFF.md`](https://github.com/getlimen/limen/blob/main/docs/HANDOFF.md) and [`limen/docs/CONVENTIONS.md`](https://github.com/getlimen/limen/blob/main/docs/CONVENTIONS.md).**

## Workflow rules (enforced, apply to every repo in `getlimen`)

- **Never work on `main`.** Create issue (labeled) → branch `<type>/<issue>_<PascalCaseName>` → PR (labeled) with `Closes #<issue>` → squash-merge + delete branch.
- **Use CLI generators whenever one exists.** `dotnet new`, `dotnet ef`, `gh issue create`, `gh pr create`, etc. If you don't know the command, search online before hand-writing boilerplate.
- **No AI / Claude attribution** in commits or PRs.

## Etymology
*Ostiarius* — Latin for **doorkeeper** or **porter**. In ancient Rome, the person whose job was to stand at the door, decide who comes in, and announce visitors. Which is exactly what a reverse proxy does: inspect, authenticate, route.

## Tech Stack

- .NET 10 / ASP.NET Core with **NativeAOT**
- Kestrel + **YARP** (Yet Another Reverse Proxy) for routing
- **LettuceEncrypt-Archon** for ACME (Let's Encrypt)
- Control plane communication: **JSON over WebSocket** to Limen (same pattern as Limentinus)
- Certificate storage: local disk volume (`/data/certs`)
- Single-binary container image (~30 MB after AOT)

## Clean architecture rules

Same as other Limen repos — see [`limen/CLAUDE.md`](https://github.com/getlimen/limen/blob/main/CLAUDE.md) for the strict layer rules. Commands/Queries-per-feature, one file per command+handler.

## Project Structure (planned; see Plan 4)

```
ostiarius/
├── contracts/                 # references Limen.Contracts NuGet
├── src/
│   ├── Ostiarius.API/         # Kestrel + YARP entry
│   ├── Ostiarius.Application/
│   ├── Ostiarius.Domain/      # CertificateRecord (disk-backed cert entity)
│   ├── Ostiarius.Infrastructure/
│   │   ├── Proxy/             # YarpConfigProvider, RouteStore, AuthMiddleware
│   │   ├── Acme/              # LettuceEncryptIntegration, FileCertificateStore
│   │   ├── Auth/              # Ed25519Verifier, RevokedTokenPoller
│   │   └── Control/           # LimenWebSocketClient
│   └── Ostiarius.Tests/
├── Dockerfile
├── README.md
├── CLAUDE.md
└── LICENSE
```

## How Ostiarius is deployed

**Not installed directly.** It's brought up by Limentinus on any node with the `proxy` role. The admin doesn't touch Ostiarius' compose directly.

When Limentinus enrolls and the node has `proxy` role, Limentinus uses its Docker API connection to pull `ghcr.io/getlimen/ostiarius:latest` and run it as a sibling container, passing the control WS URL via env.

## What Ostiarius does NOT do

- Storage of routes/services/users — that's Limen's responsibility
- Admin UI — that's Limen's Angular app
- Generating deployment commands — that's Limen too
- WireGuard — that's Forculus (hub) + Limentinus (agent)
- Auth for admin users — that's Limen's own OIDC flow; Ostiarius only handles resource-user auth (the proxy-level auth wall)

## Conventions

Same as `limen`: English-only, Apache 2.0, conventional commits, **no AI attribution in commits**.
