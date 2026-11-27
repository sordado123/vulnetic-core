# Assessment improvements — provenance

Date: 2026-11-25.

Reference reviewed: [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi),
revision `cffed9485aa1cca70762cd08a57ac62a80406258`.

The reference informed research fallbacks, executor diagnostics, selected
knowledge retrieval, progress diagnostics, and report navigation. No PentAGI
source, prompt text, assets, SDK, dependencies, or license text were incorporated.
This change extends Vulnetic's existing executor, account storage, evidence,
tool catalog and runtime. Existing notices for modified runtime code remain
applicable; see `THIRD_PARTY_NOTICES.md`.

New product code lives in `assessment/`, the assessment/research/browser adapters
under `server/`, scoped persistence under `db/`, and existing runtime/frontend
components. No dependency was added to the product's Go or frontend manifests
or lockfiles. The optional customer browser uses Playwright/Chromium already
installed on the executor; neither it nor scanners are bundled or installed
automatically by these tools.

Official Python and Playwright downloads in ignored `dist/pentagi-tests/` are
local test tooling, not release contents. Test snapshots, synthetic databases,
screenshots and the reference checkout must not enter a public source export.

Future copied components or packaged browsers/scanners require their own exact
origin, revision, license and distribution review. This record does not replace
the existing review of the complete dependency tree.
