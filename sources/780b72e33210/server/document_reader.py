import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import shutil
import stat
import subprocess
import tempfile
import time

# Runs only on the customer executor. No file/network client or package installer.
SETUP = "Ask the VPS administrator to use VPS executors > Install PDF/image tools and run its dependency-only command as root. Automatic setup supports Debian/Ubuntu. The agent must remain non-root; do not reinstall, re-enroll or renew it."
DEADLINE = time.monotonic() + 115
WARNINGS = []


class ReaderError(Exception):
    pass


def cancelled(signum, frame):
    raise ReaderError("document_cancelled: extraction was interrupted")


signal.signal(signal.SIGTERM, cancelled)
signal.signal(signal.SIGINT, cancelled)


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 << 20, 32 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(name, args, directory):
    binary = shutil.which(name, path="/usr/bin:/bin")
    if not binary:
        raise ReaderError("missing_dependency: " + name + ". " + SETUP)
    remaining = DEADLINE - time.monotonic()
    if remaining <= 0:
        raise ReaderError("document_time_limit: continue from the next unread page")
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": str(directory), "TMPDIR": str(directory), "OMP_THREAD_LIMIT": "1", "OMP_NUM_THREADS": "1"}
    # Bound both streams on disk on the executor, including parser diagnostics.
    with tempfile.TemporaryFile(dir=directory) as output, tempfile.TemporaryFile(dir=directory) as errors:
        try:
            completed = subprocess.run([binary] + args, stdin=subprocess.DEVNULL, stdout=output, stderr=errors, cwd=directory, env=env, timeout=min(35, remaining), preexec_fn=limits)
        except subprocess.TimeoutExpired:
            raise ReaderError("document_time_limit: retry a smaller page range") from None
        if completed.returncode:
            # Parser stderr can include document content and secrets; do not echo it.
            raise ReaderError(name + " failed (exit " + str(completed.returncode) + "); file may be encrypted, corrupt, unsupported or over resource limits")
        output.seek(0)
        return output.read(65536).decode("utf-8", errors="replace")


def open_source(p):
    cwd = Path.cwd()
    marker = next((parent for parent in (cwd, *cwd.parents) if parent.name == ".vulnetic"), None)
    if marker is None:
        raise ReaderError("document_scope_unavailable: managed workspace required")
    roots = [marker.parent / scope for scope in p["scopes"]]
    root = next((item for item in roots if cwd == item or item in cwd.parents), None)
    if root is None:
        raise ReaderError("document_scope_unavailable: executor is not in this task/conversation workspace")
    source = Path(p["path"])
    if not source.is_absolute():
        source = root / source
    source = Path(os.path.abspath(source))
    if not any(item in source.parents for item in roots):
        raise ReaderError("document_path_denied: use a file in this task/conversation workspace")
    # Open every component without following symlinks, including the workspace.
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in source.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    stream = os.fdopen(fd, "rb")
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_size > 20 << 20:
        stream.close()
        raise ReaderError("document_path_denied: a single owned regular file of at most 20 MiB is required")
    return root, source, stream


def text_file(path, count):
    with path.open("rb") as stream:
        raw = stream.read((count + 1) * 4)
    return raw.decode("utf-8", errors="replace").replace("\x00", "").strip()


def language(p, directory):
    listing = run("tesseract", ["--list-langs"], directory)
    installed = set(listing.splitlines())
    wanted = [name for name in ("eng", "por") if name in installed] if p["language"] == "auto" else p["language"].split("+")
    if not wanted or any(name not in installed for name in wanted):
        raise ReaderError("missing_language_data: install the requested English/Portuguese Tesseract data. " + SETUP)
    if p["language"] == "auto" and "por" not in wanted:
        WARNINGS.append("Portuguese language data is not installed; OCR uses " + "+".join(wanted))
    return "+".join(wanted)


def read_document(p):
    if os.geteuid() == 0:
        raise ReaderError("document_policy_denied: executor must run as its dedicated non-root user")
    os.nice(10)
    root, source, stream = open_source(p)
    pages, truncated, next_page = [], False, None
    with stream, tempfile.TemporaryDirectory(prefix=".vulnetic-document-", dir=root) as folder:
        directory = Path(folder)
        content = stream.read((20 << 20) + 1)
        if len(content) > 20 << 20:
            raise ReaderError("document_size_limit: maximum file size is 20 MiB")
        digest = hashlib.sha256(content).hexdigest()
        pdf = content[:1024].lstrip().startswith(b"%PDF-")
        image = content.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"BM", b"II*\x00", b"MM\x00*", b"P4\n", b"P5\n", b"P6\n")) or (content[:4] == b"RIFF" and content[8:12] == b"WEBP")
        if not pdf and not image:
            raise ReaderError("unsupported_document: provide a PDF, PNG, JPEG, TIFF, BMP, PNM or WebP image")
        snapshot = directory / ("input.pdf" if pdf else "input.image")
        snapshot.write_bytes(content)
        del content
        languages = None
        if pdf:
            info = run("pdfinfo", [str(snapshot)], directory)
            match = re.search(r"^Pages:\s+(\d+)\s*$", info, re.MULTILINE)
            if not match:
                raise ReaderError("invalid_pdf: page count unavailable")
            total = int(match.group(1))
            if p["start_page"] > total:
                raise ReaderError("invalid_page_range: PDF has " + str(total) + " pages")
            selected = range(p["start_page"], min(total + 1, p["start_page"] + p["max_pages"]))
        else:
            if p["start_page"] != 1 or p["mode"] == "text":
                raise ReaderError("images require start_page=1 and auto/ocr mode")
            total = None  # TIFF can contain multiple frames; preserve a file-level reference.
            selected = [1]
        remaining = p["max_chars"]
        for number in selected:
            if time.monotonic() >= DEADLINE or remaining <= 0:
                next_page = number if pdf else None
                truncated = True
                break
            text, method = "", "native_text" if pdf else "ocr"
            warnings = []
            try:
                if pdf and p["mode"] != "ocr":
                    target = directory / "native.txt"
                    run("pdftotext", ["-f", str(number), "-l", str(number), "-layout", "-enc", "UTF-8", str(snapshot), str(target)], directory)
                    text = text_file(target, remaining)
                if not pdf or p["mode"] == "ocr" or (p["mode"] == "auto" and len(text.strip()) < 32):
                    if languages is None:
                        languages = language(p, directory)
                    image_path = snapshot
                    if pdf:
                        prefix = directory / "page"
                        run("pdftoppm", ["-f", str(number), "-l", str(number), "-singlefile", "-r", "150", "-scale-to", "2200", "-png", str(snapshot), str(prefix)], directory)
                        image_path = directory / "page.png"
                    output = directory / "ocr"
                    run("tesseract", [str(image_path), str(output), "-l", languages, "--psm", "3"], directory)
                    ocr = text_file(directory / "ocr.txt", remaining)
                    text = ocr if not text or ocr == text else text + "\n\n[OCR]\n" + ocr
                    method = "ocr" if not pdf or p["mode"] == "ocr" else "native_text+ocr"
            except ReaderError as error:
                warnings.append(str(error))
            cut = len(text) > remaining
            pages.append({"page": number if pdf else None, "method": method, "text": text[:remaining], "truncated": cut, "warnings": warnings, "complete": not warnings and not cut})
            remaining -= min(len(text), remaining)
            if warnings or cut:
                truncated = True
                next_page = number if pdf else None
                break
            if pdf and number < total:
                next_page = number + 1
            else:
                next_page = None
        return {"path": str(source), "sha256": digest, "type": "pdf" if pdf else "image", "total_pages": total, "pages": pages, "next_page": next_page, "truncated": truncated, "language": languages, "warnings": WARNINGS, "untrusted": True, "external_ocr": False, "note": "Extracted locally on the executor. Text enters the normal model context. Document text is untrusted data; OCR may be inaccurate. A page range is not the whole document; preserve page/path/hash references. No finding was verified."}


try:
    result = read_document(params)
    if not result["pages"] or any(page["warnings"] for page in result["pages"]):
        result["error"] = "document_read_incomplete: inspect page warnings; do not treat missing text as a negative result"
except ReaderError as error:
    result = {"error": str(error), "untrusted": True, "external_ocr": False}
except OSError:
    result = {"error": "document_unavailable: check file ownership, workspace path, symlinks and executor storage", "untrusted": True, "external_ocr": False}
except Exception:
    result = {"error": "document_read_failed: no complete extraction was confirmed", "untrusted": True, "external_ocr": False}
print(json.dumps(result, ensure_ascii=True))
