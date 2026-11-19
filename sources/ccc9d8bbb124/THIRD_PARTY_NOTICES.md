# Third-party notices

Vulnetic is licensed under the GNU Affero General Public License v3.0 (see
`LICENSE`). This file lists third-party code incorporated directly into this
repository's source tree (as opposed to code pulled in as an ordinary
versioned Go module dependency, which `go.mod`/`go.sum` already track).

## `internal/norma/` — the `norma` agent SDK

**Source**: originally [`github.com/Autumn-27/norma`](https://github.com/Autumn-27/norma),
distributed at the time of incorporation via the
[`github.com/BaaRai/Norma`](https://github.com/BaaRai/Norma) fork, version
`v0.4.4`.

**License**: Apache License, Version 2.0. The full license text is included
verbatim at [`THIRD_PARTY_LICENSES/norma-APACHE-2.0.txt`](THIRD_PARTY_LICENSES/norma-APACHE-2.0.txt).

**What changed**: the package's own Go files were copied into this
repository under `internal/norma/<package>/`, and every import path
referencing `github.com/Autumn-27/norma/...` (including the package's
internal self-imports) was rewritten to
`github.com/sordado123/vulnetic/internal/norma/...`. Vulnetic also modifies
the SDK's behavior, including tool execution, operator handoff, streaming
and provider error handling, and execution recording. The SDK is therefore
a modified incorporation, not an import-path-only rewrite. Compare each
release's source revision; later changes do not describe earlier binaries.
`cmd/`'s standalone example `main` and the `examples/` directory
were not carried over (they are demos of the SDK on its own, unused by
Vulnetic). The package's own `go.mod`/`go.sum` were likewise not carried
over; its direct dependencies (`github.com/creack/pty`,
`github.com/hinshun/vt10x`, `gopkg.in/yaml.v3`) were promoted to direct
dependencies of this repository's own `go.mod` instead.

The combined application is distributed under AGPL-3.0. Original Apache-2.0
copyright, patent and attribution notices remain applicable to the SDK.
This document does not replace upstream per-file notices or certify that
every incorporated component has completed a provenance review.

## NOA / acp-kernel

`internal/norma/noa/` identifies a port of acp-kernel, including adapted
compression rules. Copyright (c) 2026 ranxianglei. Source:
https://github.com/ranxianglei/acp-kernel.

The consulted v0.0.101 license contains MIT terms plus an additional
product-surface/documentation attribution term. Its complete text is retained
in `THIRD_PARTY_LICENSES/acp-kernel-v0.0.101-LICENSE.txt`. Vulnetic uses a
port of acp-kernel; this acknowledgement preserves that attribution.
The immediate source baseline is Norma v0.4.4, commit
`7714f3d6901aa5428e24ee4cde7e1e72a6c4b7bd`. Its initial NOA port is
`35247d952a2a80889df57f0d899b64efe93773b4`; its compression-rule port is
`b996f8a491c0ccd0ff30f75ed4d49eb0451ad8c2`.
All four compression constants match acp-kernel commit
`17bf3fe05329246d114b9346eaa7ec136f06698f` after the port's documented
archive/tool-name adaptations. This is a verified content baseline, not
proof of the original author's complete working checkout.

The earlier upstream MIT license and the later additional-attribution
license are both retained in THIRD_PARTY_LICENSES. The latter was added at
`9e726fb536ff94761572822afe46cc7193b8d972` on 2026-09-27, after the dated
NOA port. Retaining both avoids concealing the license history; it does not
assert that v0.0.101 was imported. A public release must retain the
applicable notices and review the additional product-surface attribution.

## Frontend base and fonts

`web/LICENSE` retains the MIT copyright notice of Mohammed Arham Khan
(2024) for the original frontend base; a copy is retained in
`THIRD_PARTY_LICENSES/frontend-base-MIT.txt`. It does not relicense all
Vulnetic frontend modifications or the combined application as MIT.

Geist font software: Copyright (c) 2023 Vercel, in collaboration with
basement.studio; SIL Open Font License 1.1. The full text is retained in
`THIRD_PARTY_LICENSES/geist-OFL-1.1.txt`. The fonts keep their own license.

## Additional dependencies and incorporated material

Go and npm dependency licenses must be retained per distributed artifact,
including MIT/BSD/ISC/Apache notices, caniuse-lite's CC-BY-4.0 data,
simple-icons' CC0 assets and any LGPL/MPL components actually redistributed.
Their presence in a development lockfile alone does not establish shipment.
AND license expressions require all applicable terms; OR expressions offer
the alternatives stated by their authors. Copyright licenses do not grant
trademark endorsement rights.

`scripts/poc/php2shell/`: source https://github.com/ikow/php2shell-poc.
The six vendored content files match upstream trees
`35c95e7eaa5cb878f72ac8acea168495815569b6` and
`db8ff28fa6fc7d49b2207f7c988e08891d48bdf0` exactly as Git objects (the latter
adds an image outside the vendored subset). ARTEX imported this subset at
`8ad1f47549123a2cc7cf21e378455e7ec8086a17`. The initially reconstructed
notice is superseded by the upstream MIT license, Copyright (c) 2026 Qi Deng,
added at `9127065d57bde22c2f7d854029cd3b05ae927d2e`. Its text is preserved in
the vendored LICENSE and THIRD_PARTY_LICENSES/php2shell-upstream-MIT.txt.
Matching subset content does not select a unique original checkout.

The approval-detail UI credits AegisHook, https://github.com/RuoJi6/AegisHook,
in ARTEX commit `9ad323dc4c625c26506c56d04734cd6289355262`.
The comparison baseline is upstream
`f7aed12bab2f0c5533fb9ff951510231b5bf446b`, whose CallDetail.vue and MIT
license were verified. Copyright (c) 2026 RuoJi6 and AegisHook contributors.
The complete license is retained in THIRD_PARTY_LICENSES/AegisHook-MIT.txt.
This conservatively preserves upstream terms for any adapted material;
the React implementation is not claimed to be a byte-identical Vue copy,
nor does the inspiration credit identify an exact original checkout.

## ARTEX (the project this repository was forked from)

Vulnetic began as a rename and continuation of the
[ARTEX](https://github.com/Autumn-27) project by Autumn-27 (itself a public
fork maintained at [`github.com/BaaRai/ARTEX`](https://github.com/BaaRai/ARTEX)),
licensed AGPL-3.0. See the "Credits" section in `README.md` and the early
entries of `CHANGELOG.md` for the detailed attribution and release history
inherited from that project.


## shadcn stylesheet

web/src/styles/shadcn.css contains the unmodified dist/tailwind.css from
the npm package shadcn@4.12.0, with an attribution header. Source:
https://github.com/shadcn-ui/ui/tree/main/packages/shadcn.
Only the stylesheet is retained; the command-line package is not required
to build or run Vulnetic.

MIT License

Copyright (c) 2023 shadcn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
