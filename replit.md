# IoT Firmware Security Analyzer

An evidence-first workspace for safely inspecting uploaded IoT firmware and reviewing risk without retaining firmware bytes.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/firmware-analyzer` — React/Vite web app and workspace UI
- `artifacts/api-server` — Express API and static analysis pipeline
- `lib/api-spec/openapi.yaml` — source-of-truth API contract
- `lib/db/src/schema/scans.ts` — scan, inventory, and finding tables
- `artifacts/api-server/src/lib/firmware-analysis.ts` — safe static analyzer and risk scoring
- `rules/` and `ml/` — reserved extension points for updateable YARA rules and replaceable ML models

## Architecture decisions

- The first release is Replit-first, with Docker Compose documented as the future deployment path.
- Uploaded firmware is held in memory only for the active scan; retained records contain metadata, masked evidence, findings, and reports—not firmware bytes.
- Static analysis never executes extracted firmware. The initial analyzer uses safe signature, string, hash, and evidence checks and explicitly reports unavailable CVE/YARA/ML capabilities.
- NVD 2.0 is the planned CVE provider with local caching; components remain `Unknown` until reliable version evidence exists.
- Sensitive evidence is masked by default in v1, and the session surface is prepared for Clerk-backed RBAC with General User signup and Admin-controlled Analyst access.

## Product

The current vertical slice supports a dashboard upload flow, live scan progress, scan history, evidence-backed findings across the nine required vulnerability categories, SHA-256 metadata, a retained file inventory, risk scoring, printable reports, and privacy/analysis settings.

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- Multipart upload generation depends on the API Zod package compiling with the DOM library because OpenAPI binary fields generate `Blob` validation.
- The current scan worker is an in-process static-analysis worker. It is intentionally safe for the first slice but should move to a separately isolated worker before accepting untrusted production traffic at scale.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
