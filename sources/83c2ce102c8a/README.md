# Vulnetic source snapshot

Private review candidate; NOT approved for publication.

Original revision: 83c2ce102c8a397fc219fb90ba7ea1b9624ad71c. See SOURCE-SNAPSHOT.json for legal-only overlays and the outer binary-source-map.json for artifact associations.

Vulnetic derives from ARTEX by Autumn-27, maintained as an English fork by BaaRai (https://github.com/BaaRai/ARTEX). Original authors retain their rights. The combined work is under GNU AGPL v3; third-party components retain their notices and applicable licenses. See LICENSE, THIRD_PARTY_NOTICES.md and THIRD_PARTY_LICENSES.

## Build prerequisites and outline

Use Go 1.26.3 and Node.js 22 with npm. Do not connect this review tree to production.

Frontend: cd web, run npm ci, then node scripts/build-static.mjs (where available; earlier trees use NEXT_EXPORT=1 followed by npm run build). Copy web/out into server/webui/dist. Build application with CGO_ENABLED=0, GOOS=linux or windows, GOARCH=amd64: go build -trimpath -tags embedui -ldflags "-s -w -X main.version=1.1.4+5dd361d9b11d" -o <output> ./cmd/vulnetic.

Gateway: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o <output> ./cmd/vulnetic-gateway. Proof reconciler: same flags, ./cmd/vulnetic-proof-reconcile. Linux agent: GOOS=linux, GOARCH=amd64 or arm64, same stripped flags, ./cmd/vulnetic-agent. Windows foreground agent: GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-X main.version=0.2.0-preview+git.83c2ce102c8a" -o <output>.exe ./cmd/vulnetic-agent.

Select the matching revision for each command; availability differs by snapshot. These are reconstruction outlines, not executed build certification. Windows version resources and exact frontend/toolchain/VCS metadata require verification before claiming bit-identical rebuilds.

Generic deployment recipes and migrations are included under deploy/, db/ and the compose files where present. Keep SaaS RLS, the protected compose overlay, gateway isolation and unprivileged executor execution enabled. Supply fresh local credentials through environment variables; no operational credentials are included. Read the recipe before running it.

Default prompts, skills and source fixtures are retained for modification. Tools downloaded by the general Dockerfile and optional lab recipes need their own version/licensing review. This private candidate does not vendor all dependency sources; see the outer REVIEW.md for publication blockers.

## Independent reconstruction, 2026-11-17

The matching release artifacts were successfully compiled from these exported sources in a separate build directory. The frontend was generated afresh. See ../../reconstruction/results.json and ../../reconstruction/rebuild.ps1 for exact flags and measured results. These results supersede the earlier unexecuted build outline above. Windows version resources and asInvoker were checked without starting the executor. Runtime behavior and bit-identical reproduction of old releases are not certified.

Acknowledgement: Vulnetic uses a port of acp-kernel, Copyright (c) 2026 ranxianglei. See THIRD_PARTY_NOTICES.md for its verified lineage and license history.

## Final source-only distribution profile

See ../../LICENSE-RESOLUTIONS.json and ../../DEPENDENCIES.md. This source package does not distribute container images, downloaded external tools, npm packages/native libraries or generated frontend output. Historical Dockerfile/toolbox/lab recipes remain source reference and are not a cleared binary/image release. The supported reconstruction is documented in ../../reconstruction/.
