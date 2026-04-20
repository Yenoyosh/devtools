import io
import os
import tarfile
import zipfile
import hashlib
import math
import re
from typing import Optional

from flask import Flask, render_template, request, flash
from markupsafe import escape

try:
    import py7zr
except Exception:
    py7zr = None

try:
    import rarfile
except Exception:
    rarfile = None

try:
    import pefile
except Exception:
    pefile = None

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "devtools-local-secret")
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))

TEXT_EXTENSIONS = {
    ".txt", ".md", ".py", ".json", ".xml", ".html", ".htm", ".css", ".js", ".ts",
    ".java", ".kt", ".c", ".cpp", ".h", ".hpp", ".cs", ".ini", ".cfg", ".conf",
    ".log", ".csv", ".tsv", ".yml", ".yaml", ".toml", ".properties", ".sql", ".sh",
    ".bat", ".ps1", ".php", ".rb", ".go", ".rs", ".tex", ".cmd"
}

SCANNER_EXTENSIONS = {".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1", ".py", ".js", ".vbs"}
SUSPICIOUS_PATTERNS = [
    ("PowerShell encoded command", re.compile(r"-enc(odedcommand)?\b", re.I), 20),
    ("Hidden PowerShell window", re.compile(r"-windowstyle\s+hidden|-w\s+hidden", re.I), 18),
    ("Download from web", re.compile(r"(invoke-webrequest|wget|curl|bitsadmin|urlmon\.dll|downloadstring)", re.I), 16),
    ("Run from temp or appdata", re.compile(r"(%temp%|appdata|\\temp\\|/tmp/)", re.I), 10),
    ("Registry persistence", re.compile(r"(currentversion\\run|runonce|reg\s+add)", re.I), 18),
    ("Task scheduler persistence", re.compile(r"schtasks", re.I), 16),
    ("Credential or password terms", re.compile(r"(password|token|cookie|credential)", re.I), 8),
    ("Process injection terms", re.compile(r"(writeprocessmemory|createremotethread|virtualalloc(ex)?)", re.I), 30),
    ("Defender tampering terms", re.compile(r"(add-mppreference|set-mppreference|disableantispyware)", re.I), 30),
    ("Base64 blob", re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"), 10),
]
SAFE_HINT_PATTERNS = [
    ("Looks like a Python source file", re.compile(r"\b(def |class |import )", re.I)),
    ("Looks like a normal batch script", re.compile(r"@echo off|setlocal|echo ", re.I)),
]
PE_SUSPICIOUS_IMPORTS = {
    "createremotethread": 30,
    "writeprocessmemory": 30,
    "virtualallocex": 25,
    "setwindowshookexa": 18,
    "winexec": 10,
    "shellexecutew": 8,
    "urldownloadtofilea": 12,
    "urldownloadtofilew": 12,
    "internetopenurla": 8,
    "httpsendrequesta": 8,
    "adjusttokenprivileges": 16,
    "isdebuggerpresent": 10,
}


def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


@app.template_filter("format_size")
def _format_size_filter(size: int) -> str:
    return format_size(size)


def is_probably_text(raw: bytes) -> bool:
    if not raw:
        return True
    if b"\x00" in raw:
        return False
    sample = raw[:4096]
    bad = 0
    for b in sample:
        if b < 9 or 13 < b < 32:
            bad += 1
    return (bad / max(1, len(sample))) < 0.03


def decode_or_hex(filename: str, raw: bytes) -> str:
    ext = os.path.splitext(filename)[1].lower()
    likely_text = ext in TEXT_EXTENSIONS or is_probably_text(raw)
    if likely_text:
        for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
            try:
                return raw.decode(enc)[:200000]
            except Exception:
                pass

    preview = raw[:2048]
    lines = []
    for offset in range(0, len(preview), 16):
        chunk = preview[offset:offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08X}  {hex_part:<47}  {ascii_part}")
    header = [
        f"[Binary file: {filename}]",
        f"Preview: {min(len(preview), len(raw))} of {len(raw)} bytes",
        ""
    ]
    if len(raw) > 2048:
        lines.append("")
        lines.append(f"... {len(raw) - 2048} more bytes omitted ...")
    return "\n".join(header + lines)


def read_zip(file_storage):
    entries = []
    with zipfile.ZipFile(file_storage) as zf:
        for info in zf.infolist():
            if info.is_dir():
                entries.append({"path": info.filename, "size": info.file_size, "kind": "folder", "preview": "[Folder]"})
            else:
                with zf.open(info, "r") as f:
                    raw = f.read(800000)
                entries.append({
                    "path": info.filename,
                    "size": info.file_size,
                    "kind": "file",
                    "preview": decode_or_hex(info.filename, raw),
                })
    return entries


def looks_like_tar(filename: str) -> bool:
    lower = filename.lower()
    return lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2", ".tar.xz", ".txz", ".gz", ".bz2", ".xz"))


def read_tar(file_storage):
    entries = []
    file_storage.stream.seek(0)
    with tarfile.open(fileobj=file_storage.stream, mode="r:*") as tf:
        for member in tf.getmembers():
            if member.isdir():
                entries.append({"path": member.name, "size": member.size, "kind": "folder", "preview": "[Folder]"})
            elif member.isfile():
                f = tf.extractfile(member)
                raw = f.read(800000) if f else b""
                entries.append({
                    "path": member.name,
                    "size": member.size,
                    "kind": "file",
                    "preview": decode_or_hex(member.name, raw),
                })
    return entries


def read_7z(file_storage):
    if py7zr is None:
        raise RuntimeError("py7zr is not installed.")
    entries = []
    file_storage.stream.seek(0)
    with py7zr.SevenZipFile(file_storage.stream, mode="r") as z:
        names = z.getnames()
        data = z.read(names)
        for name in names:
            obj = data.get(name)
            if obj is None:
                entries.append({"path": name, "size": 0, "kind": "folder", "preview": "[Folder]"})
                continue
            raw = obj.read(800000) if hasattr(obj, "read") else bytes(obj)[:800000]
            entries.append({
                "path": name,
                "size": len(raw),
                "kind": "file",
                "preview": decode_or_hex(name, raw),
            })
    return entries


def read_rar(file_storage):
    if rarfile is None:
        raise RuntimeError("rarfile is not installed.")
    entries = []
    file_storage.stream.seek(0)
    with rarfile.RarFile(fileobj=file_storage.stream) as rf:
        for info in rf.infolist():
            if info.isdir():
                entries.append({"path": info.filename, "size": info.file_size, "kind": "folder", "preview": "[Folder]"})
            else:
                with rf.open(info) as f:
                    raw = f.read(800000)
                entries.append({
                    "path": info.filename,
                    "size": info.file_size,
                    "kind": "file",
                    "preview": decode_or_hex(info.filename, raw),
                })
    return entries


def list_archive(file_storage):
    filename = file_storage.filename or ""
    lower = filename.lower()
    if lower.endswith((".zip", ".jar", ".war", ".ear", ".apk")):
        return read_zip(file_storage)
    if looks_like_tar(lower):
        return read_tar(file_storage)
    if lower.endswith(".7z"):
        return read_7z(file_storage)
    if lower.endswith(".rar"):
        return read_rar(file_storage)
    raise RuntimeError("Unsupported archive format.")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 2)


def extract_ascii_strings(data: bytes, min_len: int = 5) -> list[str]:
    raw = re.findall(rb"[ -~]{%d,}" % min_len, data)
    return [s.decode(errors="ignore") for s in raw[:2000]]


def find_urls_ips(text: str) -> tuple[list[str], list[str]]:
    urls = re.findall(r"\bhttps?://[^\s\"']+", text, flags=re.IGNORECASE)
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    urls = list(dict.fromkeys([u.rstrip(" ).,;\"'") for u in urls]))
    ips = list(dict.fromkeys(ips))
    return urls[:50], ips[:50]


def suggest_purpose(ext: str, text: str, imports: list[str]) -> str:
    ext = ext.lower()
    joined = " ".join(imports).lower() + " " + text[:5000].lower()
    if ext in {".bat", ".cmd", ".ps1"}:
        return "Script / automation"
    if ext in {".py", ".js", ".vbs"}:
        return "Source or script file"
    if "msiexec" in joined or "install" in joined or "setup" in joined:
        return "Installer or updater"
    if ext in {".sys"}:
        return "System driver"
    if ext in {".exe", ".dll", ".com"}:
        return "Native Windows binary"
    return "Unknown"


def pe_summary(data: bytes) -> dict:
    result = {"is_pe": False, "imports": [], "notes": [], "score": 0}
    if pefile is None:
        result["notes"].append("pefile not installed, PE imports unavailable.")
        return result
    try:
        pe = pefile.PE(data=data, fast_load=False)
        result["is_pe"] = True
        imports = []
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = (entry.dll or b"").decode(errors="ignore").lower()
                if dll:
                    imports.append(dll)
                for imp in entry.imports:
                    name = (imp.name or b"").decode(errors="ignore").lower()
                    if name:
                        imports.append(name)
                        if name in PE_SUSPICIOUS_IMPORTS:
                            result["score"] += PE_SUSPICIOUS_IMPORTS[name]
                            result["notes"].append(f"Suspicious import: {name}")
        result["imports"] = list(dict.fromkeys(imports))[:120]
        if hasattr(pe, "sections"):
            for sec in pe.sections:
                name = sec.Name.decode(errors="ignore").strip("\x00").lower()
                if name in {".upx", ".packed", ".aspack", ".mpress"}:
                    result["score"] += 12
                    result["notes"].append(f"Packed-looking section: {name}")
        return result
    except Exception:
        result["notes"].append("File is not a readable PE or PE parsing failed.")
        return result


def analyze_file_bytes(filename: str, data: bytes) -> dict:
    ext = os.path.splitext(filename)[1].lower()
    text = ""
    likely_text = ext in TEXT_EXTENSIONS or is_probably_text(data)
    if likely_text:
        for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
            try:
                text = data[:500000].decode(enc)
                break
            except Exception:
                continue
        if not text:
            text = data[:500000].decode("utf-8", errors="replace")

    strings = extract_ascii_strings(data)
    joined_strings = "\n".join(strings[:400])
    scan_text = text if text else joined_strings
    urls, ips = find_urls_ips(scan_text)
    pe = pe_summary(data) if ext in {".exe", ".dll", ".sys", ".com"} or data[:2] == b"MZ" else {"is_pe": False, "imports": [], "notes": [], "score": 0}

    findings = []
    safe_hints = []
    score = pe.get("score", 0)

    for label, pattern in SAFE_HINT_PATTERNS:
        if pattern.search(scan_text[:50000]):
            safe_hints.append(label)

    for label, pattern, weight in SUSPICIOUS_PATTERNS:
        if pattern.search(scan_text[:120000]):
            score += weight
            findings.append({"label": label, "weight": weight})

    ent = entropy(data[:200000])
    if len(data) > 50000 and ent >= 7.4:
        score += 10
        findings.append({"label": f"High entropy ({ent})", "weight": 10})

    if ext and ext not in SCANNER_EXTENSIONS:
        safe_hints.append("This extension is outside the main risky executable/script set.")

    score = min(score, 100)
    if score >= 60:
        level = "High risk"
        color = "#dc2626"
        recommendation = "Do not open or run this file unless you fully trust the source and verify it elsewhere."
    elif score >= 30:
        level = "Medium risk"
        color = "#f59e0b"
        recommendation = "Treat carefully. Review the findings and only use it if the source is trustworthy."
    else:
        level = "Low risk"
        color = "#16a34a"
        recommendation = "No strong static warning signs were found, but static analysis cannot prove safety."

    return {
        "filename": filename,
        "size": len(data),
        "sha256": sha256_bytes(data),
        "extension": ext or "(none)",
        "entropy": ent,
        "likely_text": likely_text,
        "purpose": suggest_purpose(ext, scan_text, pe.get("imports", [])),
        "urls": urls,
        "ips": ips,
        "findings": findings,
        "safe_hints": safe_hints,
        "pe": pe,
        "score": score,
        "level": level,
        "color": color,
        "recommendation": recommendation,
        "preview": decode_or_hex(filename, data[:120000]),
        "strings": strings[:120],
    }


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/archive-reader", methods=["GET", "POST"])
def archive_reader():
    entries = []
    preview = ""
    selected = None

    if request.method == "POST":
        file = request.files.get("archive")
        selected = request.form.get("selected")
        if not file or not file.filename:
            flash("Please choose an archive file.")
            return render_template("archive_reader.html", entries=entries, preview=preview, selected=selected)

        try:
            entries = list_archive(file)
            entries.sort(key=lambda x: x["path"].lower())
            if entries:
                if selected is None:
                    selected = "0"
                try:
                    idx = int(selected)
                    if idx < 0 or idx >= len(entries):
                        idx = 0
                except Exception:
                    idx = 0
                selected = str(idx)
                preview = entries[idx]["preview"]
        except Exception as exc:
            flash(f"Archive could not be read: {escape(str(exc))}")

    return render_template("archive_reader.html", entries=entries, preview=preview, selected=selected)


@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    result = None
    max_upload_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    if request.method == "POST":
        file = request.files.get("sample")
        if not file or not file.filename:
            flash("Please choose a file to analyze.")
        else:
            try:
                data = file.read()
                if not data:
                    raise RuntimeError("The uploaded file is empty.")
                result = analyze_file_bytes(file.filename, data)
            except Exception as exc:
                flash(f"Analysis failed: {escape(str(exc))}")
    return render_template("scanner.html", result=result, max_upload_mb=max_upload_mb)


@app.route("/converter")
def converter():
    return render_template(
        "tool_page.html",
        title="Conv-erter",
        text="The original converter is a tkinter desktop app that drives PyInstaller and Windows EXE output. Keep that one local for now, and use the website as the public front door for the rest of your tools.",
    )


@app.route("/image-n")
def image_n():
    return render_template(
        "tool_page.html",
        title="Image-n",
        text="Your image project can come later. For a public free web service, start with the lighter tools first and add heavy torch features only after the core site is stable.",
    )


@app.route("/baser")
def baser():
    return render_template(
        "tool_page.html",
        title="Baser",
        text="This page is reserved for your future database or utility tool. Once scanner and archive reader feel solid, this can become the next real module.",
    )


@app.route("/healthz")
def healthz():
    return {"ok": True}


if __name__ == "__main__":
    app.run(debug=True)
