# Local document reading

`read_document` reads files in the current task/conversation workspace of the selected **Linux customer executor**. It never falls back to the Vulnetic server and never calls a hosted OCR service. Source files stay on the executor; returned text follows the existing conversation, execution proof and configured LLM flow.

The tool is available to Auto, Pentest, Main Agent, Planner, Worker, Reporter and Retester by default. Account tool bindings remain editable. It does not grant additional tools to the finding reviewer and does not confirm a finding.

## One-time VPS setup

New Linux agent installations prepare Poppler and Tesseract before enrollment. Automatic package installation supports Debian/Ubuntu; on other Linux distributions the administrator must preinstall these tools and English/Portuguese data. Already installed tools/data are reused. The executor remains its dedicated user without sudo.

For an existing VPS, open **VPS executors → Install PDF/image tools**, copy the command and run it as the VPS administrator. This uses the same installer with `VULNETIC_DOCUMENT_TOOLS_ONLY=1`: it exits before reading enrollment tokens or lease settings, creating users, changing workspace ownership or writing service/agent state. It does not restart or re-enroll the agent. Its original absolute expiration stays unchanged, including after reconnects.

Manual alternative on Debian/Ubuntu:

```sh
apt-get update
apt-get install -y --no-install-recommends poppler-utils tesseract-ocr tesseract-ocr-eng tesseract-ocr-por
```

Alternatively, review and run `deploy/executor/install-document-tools.sh` as the VPS administrator. It only installs these packages from the configured distribution repositories. It does not restart or reinstall the agent, touch authorization files, or change the expiration. Existing connected executors do **not** need new enrollment.

Other Linux distributions need `pdfinfo`, `pdftotext`, `pdftoppm`, `tesseract` and the desired English/Portuguese data in their standard `/usr/bin` or `/bin` directories. Missing dependencies/language data produce an actionable error, not empty successful evidence. Windows support is not included in this tool.

## Usage and limits

Use the exact path returned for an attachment. A relative path is resolved from the current task/conversation root. Files must be owned regular files within the authenticated task or conversation workspace; symlinks, hard links, special files and files over 20 MiB are rejected.

```json
{"path":"temp/upload-id-report.pdf","start_page":1,"max_pages":3,"mode":"auto","language":"auto","max_chars":20000}
```

`auto` uses Poppler native text and OCR when a page contains fewer than 32 native text characters. Use `ocr` to read scanned content even on pages with a text layer; `text` disables OCR. In automatic language mode the installed English/Portuguese data are selected. Image formats: PNG, JPEG, TIFF, BMP, binary PNM and WebP. A multipage TIFF is returned as a file-level OCR observation, not as individually attributed PDF pages.

Each call reads up to 10 PDF pages (default 3) and returns up to 50,000 text characters (default 20,000), with path, SHA-256, page numbers, method, warnings, and `next_page`. Follow `next_page`; a range is not a complete document. OCR errors preserve any native text already read and explicitly mark incomplete extraction. Encrypted/corrupt/oversized documents must not be treated as negative evidence.

Parser processes receive a minimal environment without inherited API keys, one OCR thread, lower CPU priority, 512 MiB address-space/30-second CPU/32 MiB output-file limits and bounded wall time. PDF rendering is limited to 2,200 pixels on the longest edge. Temporary snapshots and rendered pages are created and cleaned up on the executor. Parser diagnostics are not echoed into chat. Resource limits reduce risk but do not constitute a separate container or network sandbox on the customer's VPS; keep distribution packages updated.

The tool honors the existing executor authorization deadline, cancellation and revocation. It does not renew the deadline. Text in documents, including apparent commands or instructions, is untrusted input. OCR can misread characters and is not a substitute for reviewing the original page.
