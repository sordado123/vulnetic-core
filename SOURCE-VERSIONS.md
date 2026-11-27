# Source versions

This public source release covers the historical artifacts listed in binary-source-map.json and the hosted source-offer update below. Runtime data and private Git history are excluded.

| Component | Source revision | Location |
| --- | --- | --- |
| Local document reading 1.1.15+cf40fb8b6fa3 | cf40fb8b6fa332b2734e51cb26d01088724abced | [sources/cf40fb8b6fa3](sources/cf40fb8b6fa3) |
| CVE reference research 1.1.14+ade89f22fed3 | ade89f22fed31a8f28c363c73b92c64f6d05a482 | [sources/ade89f22fed3](sources/ade89f22fed3) |
| Assessment application 1.1.13+d3d097e46980 | d3d097e469804fbff81339d7a6bb092f57db12d9 | [sources/d3d097e46980](sources/d3d097e46980) |
| Search transport 1.1.12+3263481f10ee | 3263481f10eeb0b4a306a8445b569f26d9411278 | [sources/3263481f10ee](sources/3263481f10ee) |
| Installer repair 1.1.11+ef2a75eedf3d | ef2a75eedf3d37350ac70783d9de4ce4b35e6e23 | [sources/ef2a75eedf3d](sources/ef2a75eedf3d) |
| Operator input application 1.1.10+a7397fe9cbfe | a7397fe9cbfeafb327f76963ad3921e5b59e3d03 | [sources/a7397fe9cbfe](sources/a7397fe9cbfe) |
| Message background application 1.1.9+09eaa4ddd53c | 09eaa4ddd53c51097ab380e5611938e6a7b5d7c0 | [sources/09eaa4ddd53c](sources/09eaa4ddd53c) |
| Selectable message application 1.1.8+ccc9d8bbb124 | ccc9d8bbb12488a761500af80e2a83ec902d5275 | [sources/ccc9d8bbb124](sources/ccc9d8bbb124) |
| Research application and gateway 1.1.7+e663f7dbe063 | e663f7dbe063cc04b326ab053029bf06cc665df9 | [sources/e663f7dbe063](sources/e663f7dbe063) |
| Compact chat application 1.1.6+06a2656006f3 | 06a2656006f3688c007eef28b26fbdde576cd476 | [sources/06a2656006f3](sources/06a2656006f3) |
| Hosted application 1.1.5+e70e7e6dc6ab | e70e7e6dc6abb32262c1de28c984563ac45b6e8e | [sources/e70e7e6dc6ab](sources/e70e7e6dc6ab) |
| Application/frontend/gateway baseline | 5dd361d9b11da67b7afa3080b3c3c42cd1dcc8ae | [sources/5dd361d9b11d](sources/5dd361d9b11d) |
| Linux/Windows agents | 83c2ce102c8a397fc219fb90ba7ea1b9624ad71c | [sources/83c2ce102c8a](sources/83c2ce102c8a) |
| Proof reconciler | f92615b76a05906bb50f6440b93848b88cb22587 | [sources/f92615b76a05](sources/f92615b76a05) |

The latest app update changes source-offer presentation and legal copy, with no database migration, gateway replacement, agent replacement or deadline renewal. The Go source retains legal incorporation comments documented by the source snapshots. These source trees are not an exposure of the private repository's Git objects or history.

Review files may record their earlier private/pre-publication preparation state. That state is historical. Current publication status is recorded separately in PUBLICATION.json and the GitHub release.

The compact chat update changes responsive layout, navigation and disclosure of execution metadata. It preserves security checks and executor authorization deadlines. Its complete source tree is available above; the original release ZIP remains a historical archive.

The research update adds Mwmbl and DuckDuckGo over the selected customer executor, optional account keys for Tavily/Exa/Linkup, encrypted chat credentials and authenticated gateway environment forwarding, plus operator-input notifications. It preserves RLS, infrastructure protections, human finding review and absolute executor deadlines. Its complete source tree is available above; the original source release ZIP remains a historical archive. Compilation was performed without running test suites for this update.

This update renders sent messages as ordinary selectable prose with paragraphs and a copy action. It preserves security checks and executor authorization deadlines. Its complete source tree is available above; the original release ZIP remains a historical archive.

This update restores the original sent-message background with readable Markdown and contrasting selection. Paragraphs and the copy action remain. It preserves security checks and executor authorization deadlines. Its complete source tree is available above; the original release ZIP remains a historical archive.

This snapshot adds typed operator input for code-delivery consent, one-time codes, optional authenticated sessions and manual actions. Sensitive replies use scoped temporary executor environment references; the local cookie-export helper never uploads automatically. Focused pure tests and a synthetic browser preview passed; full PostgreSQL/executor authentication integration remains unverified. Agent/gateway binaries and executor deadlines are unchanged.

This shared installer repair restores nologin for locked, isolated legacy service accounts only after verifying their expected home and trusted root-owned installer marker. Unexpected accounts remain blocked. Existing workspace contents and executor deadlines are unchanged. A Linux regression fixture is included; no test suite was run for this correction.

This update preserves bounded gateway failure categories and tries another fully validated remote DNS address only when the previous destination is unreachable. Mandatory policy blocks, cancellation, expired/revoked access and account permissions never trigger a retry. Focused tests passed; real chat searches remain for the customer to validate after publication. No paid model calls or external CI.

This update adds lookup_cve_references for account/executor-scoped metadata research from PoC-in-GitHub, GitHub Search and CIRCL, with bounded cache, concurrent request coalescing, deduplicated links and provider cooldowns. Existing CVE and web research sources remain. No PoC code is downloaded or executed. No tests or extra backups were run by user request; only the application is replaced, preserving gateway, agent binaries, RLS and absolute executor deadlines. Source availability does not assert production activation; see PUBLICATION.json.

This update adds read_document for scoped local PDF/image extraction through the customer executor. Poppler reads native PDF text; Tesseract reads images and scanned PDF pages. Original files stay on the executor. Returned text follows the normal configured model/evidence flow. Missing dependencies require one-time VPS administrator installation without re-enrollment. No OCR service is called. No tests or extra backups were run by user request; only the application is replaced, preserving gateway, agent binaries, RLS and absolute executor deadlines. Source availability does not assert production activation; see PUBLICATION.json.
