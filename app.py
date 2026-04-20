
import io
import os
import tarfile
import zipfile
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

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "devtools-local-secret")

TEXT_EXTENSIONS = {
    ".txt", ".md", ".py", ".json", ".xml", ".html", ".htm", ".css", ".js", ".ts",
    ".java", ".kt", ".c", ".cpp", ".h", ".hpp", ".cs", ".ini", ".cfg", ".conf",
    ".log", ".csv", ".tsv", ".yml", ".yaml", ".toml", ".properties", ".sql", ".sh",
    ".bat", ".ps1", ".php", ".rb", ".go", ".rs", ".tex"
}

MAX_PREVIEW_BYTES = 800_000
HEX_PREVIEW_BYTES = 2048


def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


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

    preview = raw[:HEX_PREVIEW_BYTES]
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
    if len(raw) > HEX_PREVIEW_BYTES:
        lines.append("")
        lines.append(f"... {len(raw) - HEX_PREVIEW_BYTES} more bytes omitted ...")
    return "\n".join(header + lines)


def read_zip(file_storage):
    entries = []
    with zipfile.ZipFile(file_storage) as zf:
        for info in zf.infolist():
            if info.is_dir():
                entries.append({"path": info.filename, "size": info.file_size, "kind": "folder", "preview": "[Folder]"})
            else:
                with zf.open(info, "r") as f:
                    raw = f.read(MAX_PREVIEW_BYTES)
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
                raw = f.read(MAX_PREVIEW_BYTES) if f else b""
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
            raw = obj.read(MAX_PREVIEW_BYTES) if hasattr(obj, "read") else bytes(obj)[:MAX_PREVIEW_BYTES]
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
                    raw = f.read(MAX_PREVIEW_BYTES)
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

    return render_template("archive_reader.html", entries=entries, preview=preview, selected=selected, format_size=format_size)


@app.route("/scanner")
def scanner():
    return render_template("tool_page.html", title="Scan-ner", text="This Render starter already includes the page. The original desktop version uses PySide6 plus requests and pefile, so for the web version you should move the scan logic into Flask routes and keep the UI in HTML.")


@app.route("/converter")
def converter():
    return render_template("tool_page.html", title="Conv-erter", text="The original converter is a tkinter desktop app that drives PyInstaller. That is best kept as a local desktop tool, not a free public web service. You can still keep this page as a landing/info page.")


@app.route("/image-n")
def image_n():
    return render_template("tool_page.html", title="Image-n", text="Your image / diffusion project depends on torch, torchvision and Pillow. That is usually too heavy for a Render free web service, so add it later or move it to a stronger paid instance.")


@app.route("/baser")
def baser():
    return render_template("tool_page.html", title="Baser", text="Use this page as a placeholder for your future baser tool. You can add forms and Flask routes here later.")


@app.route("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
