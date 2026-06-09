#!/usr/bin/env python3
"""
Update version.json based on APK files in channel directories.

Parses APK filenames to extract version info, computes file size and MD5 hash,
and updates the corresponding version.json file.

Filename format: {channel}_{type}_v{version}.apk
  - channel: must match the directory name (e.g., online, pda, vivo, wear)
  - type:    must be "release" for production publishing; other types abort
  - version: YY.MM.DDX  (X = build index of the day, 0-based)

Usage:
  python update_version.py [channel ...]

  channel: One or more channel names to process.
           If omitted, all directories containing .apk files are processed.
"""

import hashlib
import json
import os
import re
import struct
import sys
import zipfile
from pathlib import Path


def _find_repo_root() -> Path:
    """Locate the repository root by walking up from this script until a .git directory or file is found."""
    p = Path(__file__).resolve().parent
    while True:
        git = p / ".git"
        if git.is_dir() or git.is_file():
            return p
        parent = p.parent
        if parent == p:
            raise SystemExit("FATAL: cannot locate repository root (no .git found)")
        p = parent


REPO_ROOT = _find_repo_root()
APK_ROOT = REPO_ROOT / "apk"
GITHUB_BASE = "https://github.com/xsydaima/MatrixAPK/blob/main"

DEFAULT_META = {
    "app_name": "呆马",
    "application_id": "com.daima.im.ai",
    "application_scheme": "aily",
    "version_description": "优化已知问题",
    "app_logo": "",
}

# ---------------------------------------------------------------------------
# AXML (binary AndroidManifest.xml) parser – extracts package name
# ---------------------------------------------------------------------------

RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_ELEMENT_TYPE = 0x0102
TYPE_STRING = 3


class AXMLParser:
    """Minimal parser for binary AndroidManifest.xml to get the package name."""

    def __init__(self, data: bytes):
        self.data = data
        self.strings: list[str] = []

    def _u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def parse(self) -> str | None:
        off = 0
        if self._u16(off) != RES_STRING_POOL_TYPE:
            return None

        chunk_size = self._u32(off + 4)
        string_count = self._u32(off + 8)
        flags = self._u32(off + 16)
        strings_start = self._u32(off + 20)
        is_utf8 = bool(flags & 0x0100)

        # read string offsets (right after the header, which is 28 bytes for string pool)
        offs_begin = off + 28
        str_offsets = [self._u32(offs_begin + i * 4) for i in range(string_count)]

        # read strings
        data_base = off + strings_start
        for i in range(string_count):
            self.strings.append(self._read_str(data_base + str_offsets[i], is_utf8))

        off += chunk_size
        # skip resource map chunk if present
        if off < len(self.data) and self._u16(off) == RES_XML_RESOURCE_MAP_TYPE:
            off += self._u32(off + 4)

        # walk nodes until we hit the <manifest> start-element
        while off < len(self.data):
            typ = self._u16(off)
            if typ == RES_XML_START_ELEMENT_TYPE:
                pkg = self._parse_element(off)
                if pkg:
                    return pkg
            off += self._u32(off + 4)

        return None

    def _read_str(self, offset: int, is_utf8: bool) -> str:
        if is_utf8:
            b0 = self.data[offset]
            if b0 & 0x80:
                byte_len = ((b0 & 0x7F) << 8) | self.data[offset + 1]
                start = offset + 2
            else:
                byte_len = b0
                start = offset + 1
            return self.data[start : start + byte_len].decode("utf-8", errors="replace")
        else:
            char_len = self._u16(offset)
            start = offset + 2
            return self.data[start : start + char_len * 2].decode("utf-16-le", errors="replace")

    def _parse_element(self, offset: int) -> str | None:
        """Parse a start-element chunk.  Returns package name if this is <manifest>."""
        header_size = self._u16(offset + 2)  # 16 for element nodes
        # element-specific fields start at offset + header_size
        e = offset + header_size  # shortcuts below assume this layout

        ns_idx = self._u32(e)
        name_idx = self._u32(e + 4)
        name = self.strings[name_idx] if name_idx < len(self.strings) else ""

        if name != "manifest":
            return None

        attr_start = self._u16(e + 8)
        attr_size = self._u16(e + 10)
        attr_count = self._u16(e + 12)
        attr_base = offset + attr_start

        for i in range(attr_count):
            a = attr_base + i * attr_size
            a_name_idx = self._u32(a + 4)
            a_raw = self._u32(a + 8)
            # Res_value: u16 size, u8 res0(0), u8 dataType, u32 data
            a_type = self.data[a + 13]
            a_data = self._u32(a + 14)

            aname = self.strings[a_name_idx] if a_name_idx < len(self.strings) else ""
            if aname == "package":
                if a_type == TYPE_STRING and a_data < len(self.strings):
                    return self.strings[a_data]
                elif a_raw != 0xFFFFFFFF and a_raw < len(self.strings):
                    return self.strings[a_raw]

        return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_RE_FILENAME = re.compile(
    r"^([a-zA-Z0-9]+)_(release|debug|alpha|beta|internal)_v(\d{2}\.\d{2}\.\d{3})\.apk$"
)


def parse_filename(filename: str) -> tuple[str, str, str] | None:
    """Return (channel, type, version) or None."""
    m = _RE_FILENAME.match(filename)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def md5_file(filepath: str) -> str:
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_package_name(apk_path: str) -> str | None:
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            manifest_data = z.read("AndroidManifest.xml")
        return AXMLParser(manifest_data).parse()
    except Exception:
        return None


def find_apks(channel_dir: Path) -> list[tuple[str, str, str, str]]:
    """Return [(filename, channel, type, version), ...] for valid APK names."""
    results = []
    for f in os.listdir(channel_dir):
        if not f.endswith(".apk"):
            continue
        p = parse_filename(f)
        if p:
            results.append((f, p[0], p[1], p[2]))
    return results


def load_existing_json(channel_dir: Path) -> dict | None:
    path = channel_dir / "version.json"
    if path.is_file():
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return None


# ---------------------------------------------------------------------------
# main logic
# ---------------------------------------------------------------------------

def process_channel(channel: str) -> bool:
    channel_dir = APK_ROOT / channel
    if not channel_dir.is_dir():
        print(f"[ERROR] directory not found: {channel_dir}")
        return False

    apks = find_apks(channel_dir)
    if not apks:
        print(f"[WARN] no valid APK files in {channel_dir}")
        return False

    for filename, ch, typ, _ver in apks:
        if ch != channel:
            print(f"[ERROR] channel mismatch in filename '{filename}': "
                  f"expected '{channel}', got '{ch}'")
            return False
        if typ != "release":
            print(f"[ERROR] NON-RELEASE APK DETECTED – publishing prohibited: {filename}")
            print(f"        type '{typ}' is not allowed; only 'release' may be published.")
            return False

    apks.sort(key=lambda x: x[0])
    filename, ch, typ, version = apks[-1]
    apk_path = channel_dir / filename

    existing = load_existing_json(channel_dir)
    old_data = existing.get("data", {}) if existing else {}

    file_size = os.path.getsize(apk_path)
    md5 = md5_file(str(apk_path))
    pkg = extract_package_name(str(apk_path))

    app_name = old_data.get("app_name", DEFAULT_META["app_name"])
    app_id = pkg or old_data.get("application_id", DEFAULT_META["application_id"])
    scheme = old_data.get("application_scheme", DEFAULT_META["application_scheme"])
    desc = old_data.get("version_description", DEFAULT_META["version_description"])
    logo = old_data.get("app_logo", DEFAULT_META["app_logo"])
    other_urls = old_data.get("other_download_url", [])
    share_url = old_data.get("share_url", "")
    download_times = old_data.get("download_times", 0)

    download_url = f"{GITHUB_BASE}/apk/{channel}/{filename}"

    data = {
        "status": 1,
        "info": "",
        "data": {
            "new_version": version,
            "cur_version": version,
            "package_size": file_size,
            "package_name": app_id,
            "download_url": download_url,
            "cdn_download_url": download_url,
            "other_download_url": other_urls,
            "share_url": share_url,
            "download_times": download_times,
            "apk_local_path": "",
            "apk_md_5_hash": md5,
            "apk_last_update_on": 0,
            "apk_last_update_status": 0,
            "apk_last_update_error": "",
            "client_force_update": 0,
            "update_flag": False,
            "have_new_version": False,
            "version_description": desc,
            "app_logo": logo,
            "app_name": app_name,
            "application_id": app_id,
            "application_scheme": scheme,
        },
    }

    print(f"[INFO] {filename}")
    print(f"       channel   : {channel}")
    print(f"       version   : {version}")
    print(f"       size      : {file_size:,} bytes")
    print(f"       MD5       : {md5}")
    print(f"       package   : {app_id}")
    print(f"       download  : {download_url}")

    json_path = channel_dir / "version.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f"       -> updated : {json_path}")

    return True


def main() -> None:
    if len(sys.argv) > 1:
        channels = sys.argv[1:]
    else:
        # auto-detect: all directories directly under repo root that contain .apk files
        channels = sorted(
            d.name
            for d in APK_ROOT.iterdir()
            if d.is_dir()
            and any(f.endswith(".apk") for f in os.listdir(d) if os.path.isfile(d / f))
        )

    if not channels:
        print("[ERROR] no channels found.  Pass channel name(s) as arguments.")
        sys.exit(1)

    ok = True
    for ch in channels:
        if not process_channel(ch):
            ok = False
        print()

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
