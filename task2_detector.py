"""
SEC530 - Project 3: Smart Compression Archive Analyzer
Task 2: Static Rule-Based Detection Script  (v3.0 — fully revised)

Classifies an archive as BENIGN / SUSPICIOUS / MALICIOUS
based on features extracted by Task 1.

CVE coverage: 2004 – 2025  (R01–R47, R50–R51)
All CVE assignments verified against NVD/vendor advisories.

Usage:
    python task2_detector.py <feature_json_file>
    python task2_detector.py <feature_json_file> --output report.json
    python task2_detector.py --batch  <directory_of_jsons>
    python task2_detector.py --suite  <test_suite_json>
"""

from __future__ import annotations

import json
import argparse
import sys
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


# ──────────────────────────────────────────────
#  DATA STRUCTURES
# ──────────────────────────────────────────────

@dataclass
class RuleHit:
    rule_id:     str
    severity:    str          # LOW / MEDIUM / HIGH / CRITICAL
    description: str
    evidence:    str
    cve:         Optional[str] = None
    rationale:   str = ""     # Why this rule indicates malice


@dataclass
class DetectionReport:
    file_name:        str
    file_path:        str
    classification:   str         # BENIGN / SUSPICIOUS / MALICIOUS
    severity_score:   int         # 0–100
    risk_level:       str         # LOW / MEDIUM / HIGH / CRITICAL
    triggered_rules:  list[RuleHit] = field(default_factory=list)
    explanation:      str = ""
    analysis_timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )


# ──────────────────────────────────────────────
#  SEVERITY WEIGHTS
# ──────────────────────────────────────────────

SEVERITY_WEIGHT: dict[str, int] = {
    "LOW":      5,
    "MEDIUM":  15,
    "HIGH":    30,
    "CRITICAL": 50,
}

# ──────────────────────────────────────────────
#  EXTENSION SETS
# ──────────────────────────────────────────────

EXECUTABLE_EXTENSIONS: set[str] = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".js", ".jse",
    ".vbs", ".vbe", ".scr", ".jar", ".msi", ".com", ".pif",
    ".hta", ".wsf", ".wsh", ".cpl", ".inf", ".reg",
    ".sys", ".drv", ".ocx", ".gadget",
}

SCRIPT_EXTENSIONS: set[str] = {
    ".ps1", ".bat", ".cmd", ".sh", ".bash", ".py",
    ".vbs", ".js", ".jse", ".vbe", ".wsf", ".wsh",
    ".hta", ".pl", ".rb", ".php", ".lua", ".tcl",
}

MACRO_EXTENSIONS: set[str] = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
    ".xlam", ".doc", ".xls", ".ppt",
}

SHORTCUT_EXTENSIONS: set[str] = {".lnk", ".url", ".desktop"}

ARCHIVE_EXTENSIONS: set[str] = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".xz", ".cab", ".iso", ".tgz", ".tbz2", ".ace",
    ".arj", ".lzh", ".lha",
}

DECOY_EXTENSIONS: set[str] = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".png", ".jpg", ".jpeg", ".gif", ".txt",
}

# ──────────────────────────────────────────────
#  KEYWORD LISTS
# ──────────────────────────────────────────────

DOWNLOADER_KEYWORDS: list[str] = [
    "invoke-webrequest", "downloadstring", "downloadfile",
    "urldownloadtofile", "bitsadmin", "certutil",
    "wget", "curl", "net.webclient",
    "xmlhttp", "winhttprequest", "adodb.stream",
    "start-bitstransfer", "webclient", "httpclient",
    "ftpwebrequest", "bits.manager",
]

EXECUTION_KEYWORDS: list[str] = [
    "wscript.shell", "shell.application", "createobject",
    "cmd.exe", "powershell", "mshta", "regsvr32",
    "rundll32", "cscript", "wscript", "exec",
    "shellexecute", "winexec", "createprocess",
    "ntcreateuserprocess", "rtlcreateuserthread",
    "createremotethread", "virtualalloc",
]

OBFUSCATION_KEYWORDS: list[str] = [
    "base64", "frombase64string", "convert]::frombase64",
    "char(", "chr(", "charcode", "-enc ", "-encodedcommand",
    "iex(", "invoke-expression", "\\x",
    "decompress", "gzipstream", "memorystream",
    "reflection.assembly", "system.reflection",
    "bitconverter", "-nop ", "-noprofile",
    "hidden", "-windowstyle hidden", "bypass",
    "set-executionpolicy bypass",
]

PHISHING_KEYWORDS: list[str] = [
    "invoice", "payment", "urgent", "bank", "account",
    "verify", "suspended", "click here", "confirm",
    "password", "credential", "login", "update required",
    "receipt", "refund", "overdue", "wire transfer",
    "kyc", "compliance", "notice", "alert",
]

SUSPICIOUS_DIRNAMES: list[str] = [
    "temp", "tmp", "appdata", "roaming", "startup",
    "system32", "syswow64", "windows", "programdata",
    "prefetch", "tasks", "scheduled tasks",
]

# Format-string pattern for R45
_FMT_STR_RE = re.compile(r"%[0-9]*[sdfxpn]")

# URL / IP pattern for R29
_URL_RE = re.compile(
    r"(https?://[^\s\"'<>]{4,}"
    r"|ftp://[^\s\"'<>]{4,}"
    r"|(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?)"
)

# Timestamp year extractor
_YEAR_RE = re.compile(r"(\d{4})")


# ──────────────────────────────────────────────
#  HELPER UTILITIES
# ──────────────────────────────────────────────

def get_extension(filename: str) -> str:
    """Return the final (lowest) extension, lower-cased."""
    return Path(filename).suffix.lower()


def get_all_extensions(filename: str) -> list[str]:
    """Return all suffixes, lower-cased."""
    return [s.lower() for s in Path(filename).suffixes]


def has_rtlo(filename: str) -> bool:
    """True if the Right-to-Left Override char (U+202E) is present."""
    return "\u202e" in filename


def is_padded_with_spaces(filename: str) -> bool:
    """True if the stem contains 5+ consecutive spaces (extension-hiding trick)."""
    return "     " in Path(filename).stem


def contains_keyword(text: str, keywords: list[str]) -> list[str]:
    lower = text.lower()
    return [kw for kw in keywords if kw in lower]


def has_non_ascii_exec(filename: str, exec_exts: set[str]) -> bool:
    """True if filename has non-ASCII chars AND an executable extension."""
    return (
        any(ord(c) > 127 for c in filename)
        and get_extension(filename) in exec_exts
    )


def has_format_string(filename: str) -> bool:
    return bool(_FMT_STR_RE.search(filename))


# ──────────────────────────────────────────────
#  FEATURE NORMALIZER
#
#  Maps Task 1 JSON structure → flat dict used by the rule engine.
# ──────────────────────────────────────────────

def normalize_features(raw: dict) -> dict:
    basic   = raw.get("1_basic_info", {})
    meta    = raw.get("2_archive_metadata", {})
    files   = raw.get("3_internal_files", [])
    sec     = raw.get("4_security_indicators", {})
    content = raw.get("5_content_indicators", {})

    normalized_files: list[dict] = []
    for fi in files:
        normalized_files.append({
            "name":              fi.get("internal_path") or fi.get("file_name", ""),
            "compressed_size":   fi.get("compressed_size", 0),
            "uncompressed_size": fi.get("uncompressed_size", 0),
            "timestamp":         fi.get("timestamp", ""),
            "entropy":           fi.get("entropy", 0.0),
            "is_directory":      fi.get("is_directory", False),
            "detected_mime":     fi.get("detected_mime", ""),
            "is_hidden":         fi.get("is_hidden", False),
            "has_double_extension":    fi.get("has_double_extension", False),
            "is_executable_or_script": fi.get("is_executable_or_script", False),
        })

    extracted_strings: list[str] = (
        content.get("urls_found", []) +
        content.get("suspicious_commands", [])
    )

    total_uncompressed = sum(
        fi.get("uncompressed_size", 0) for fi in files
    )

    return {
        # identity
        "file_name":  basic.get("file_name", "unknown"),
        "file_path":  basic.get("file_path", ""),
        "file_size":  basic.get("file_size", 0),
        "mime_type":  basic.get("mime_type", ""),
        "hashes":     basic.get("hashes", {}),

        # archive-level metadata
        "archive_format":          meta.get("format", "unknown"),
        "compression_ratio":       float(meta.get("compression_ratio", 0)),
        "is_encrypted":            meta.get("password_protected", False),
        "is_split":                meta.get("is_split_archive", False),
        "is_corrupted":            meta.get("corrupted", False),
        "file_count":              meta.get("file_count", len(files)),
        "archive_comment":         meta.get("comment") or "",
        "total_uncompressed_size": total_uncompressed,

        # Task-1 pre-computed flags
        "max_nested_depth":        sec.get("max_nesting_depth", 0),
        "t1_has_executables":      sec.get("has_executables", False),
        "t1_has_office_macros":    sec.get("has_office_macros", False),
        "t1_has_lnk":              sec.get("has_lnk", False),
        "t1_has_nested_archives":  sec.get("has_nested_archives", False),
        "t1_double_extensions":    sec.get("double_extensions", []),
        "t1_suspicious_filenames": sec.get("suspicious_filenames", []),
        "t1_unicode_rtlo":         sec.get("unicode_rtlo_detected", False),
        "t1_extension_mismatches": sec.get("extension_mismatches", []),
        "t1_archive_bomb":         sec.get("archive_bomb_suspected", False),
        "t1_decoy_and_exe":        sec.get("decoy_and_executable_combo", False),

        # per-file list + string indicators
        "files":             normalized_files,
        "extracted_strings": extracted_strings,
    }


# ──────────────────────────────────────────────
#  RULE ENGINE
# ──────────────────────────────────────────────

class ArchiveRuleEngine:
    """
    Runs all detection rules against a normalized feature dict.

    Naming convention:  rule_R<nn>_<short_name>

    Every rule method must call self._add(...) if the rule fires and
    return without raising.  Exceptions are caught in run_all_rules().
    """

    def __init__(self, features: dict) -> None:
        self.f         = features
        self.hits:     list[RuleHit] = []
        self.files:    list[dict]    = features.get("files", [])
        self.strings:  list[str]     = features.get("extracted_strings", [])
        self.filenames: list[str]    = [fi.get("name", "") for fi in self.files]

    # ── internal helpers ──────────────────────────────────────────

    def _add(
        self,
        rule_id:     str,
        severity:    str,
        description: str,
        evidence:    str,
        cve:         Optional[str] = None,
        rationale:   str = "",
    ) -> None:
        self.hits.append(
            RuleHit(rule_id, severity, description, evidence, cve, rationale)
        )

    def _files_with_ext(self, ext_set: set[str]) -> list[str]:
        return [fn for fn in self.filenames if get_extension(fn) in ext_set]

    def _strings_blob(self) -> str:
        return " ".join(self.strings).lower()

    # ── R01 ───────────────────────────────────────────────────────
    def rule_R01_executable_files(self) -> None:
        """
        Executable / binary files present inside the archive.

        Rationale: Legitimate archives rarely need .exe / .dll / .scr
        inside them.  Attackers pack executables in archives to bypass
        email gateway filters and to deliver malware to disk via
        trusted archiving software.

        Source: filenames (extension check) + t1_has_executables flag.
        """
        found = self._files_with_ext(EXECUTABLE_EXTENSIONS)
        if found or self.f.get("t1_has_executables"):
            evidence = found[:5] if found else ["(flagged by Task-1 extractor)"]
            self._add(
                "R01", "HIGH",
                "Archive contains executable or binary files.",
                f"Files: {evidence}",
                rationale=(
                    "Executables bundled in archives are a primary delivery "
                    "mechanism for malware; they bypass email attachment "
                    "filters that block .exe directly."
                ),
            )

    # ── R02 ───────────────────────────────────────────────────────
    def rule_R02_script_files(self) -> None:
        """
        Script files present (.ps1, .bat, .vbs, .sh, etc.).

        Rationale: Scripts can execute arbitrary OS commands on open /
        double-click.  Attackers frequently deliver PowerShell or VBS
        loaders via archives.

        Source: filenames (extension check).
        """
        found = self._files_with_ext(SCRIPT_EXTENSIONS)
        if found:
            self._add(
                "R02", "MEDIUM",
                "Archive contains script files that can execute OS commands.",
                f"Files: {found[:5]}",
                rationale=(
                    "Script files (.ps1, .vbs, .bat, .sh …) execute with "
                    "user-level privileges on double-click and are widely "
                    "abused as first-stage loaders."
                ),
            )

    # ── R03 ───────────────────────────────────────────────────────
    def rule_R03_shortcut_files(self) -> None:
        """
        Shortcut files (.lnk / .url / .desktop) present.

        Rationale: Shortcut files contain arbitrary command-line targets
        and are exploited to silently execute payloads while showing
        a benign-looking icon.

        CVE-2023-36025: Windows SmartScreen bypass via crafted .url
        files — exploited in the wild by Phemedrone Stealer, DarkGate.

        Source: filenames (extension check) + t1_has_lnk flag.
        """
        found = self._files_with_ext(SHORTCUT_EXTENSIONS)
        if found or self.f.get("t1_has_lnk"):
            evidence = found[:5] if found else ["(flagged by Task-1 extractor)"]
            self._add(
                "R03", "HIGH",
                "Shortcut files (.lnk/.url/.desktop) present — can execute hidden payloads.",
                f"Files: {evidence}",
                cve="CVE-2023-36025",
                rationale=(
                    "Shortcut files store arbitrary command targets. "
                    "CVE-2023-36025 allows crafted .url files to bypass "
                    "Windows SmartScreen entirely, executing malware without "
                    "any security warning."
                ),
            )

    # ── R04 ───────────────────────────────────────────────────────
    def rule_R04_double_extension(self) -> None:
        """
        Double-extension filenames (e.g. invoice.pdf.exe).

        Rationale: Windows hides known extensions by default.
        'invoice.pdf.exe' appears as 'invoice.pdf' in Explorer,
        tricking users into believing they are opening a document.

        Source: filenames (all suffixes) + t1_double_extensions list.
        """
        own: list[str] = []
        for fn in self.filenames:
            exts = get_all_extensions(fn)
            if len(exts) >= 2:
                if (exts[-1] in EXECUTABLE_EXTENSIONS
                        and exts[-2] in DECOY_EXTENSIONS):
                    own.append(fn)

        all_hits = list(set(own + self.f.get("t1_double_extensions", [])))
        if all_hits:
            self._add(
                "R04", "CRITICAL",
                "Double-extension filenames disguise executables as documents.",
                f"Files: {all_hits[:5]}",
                rationale=(
                    "Windows hides known extensions by default; 'report.pdf.exe' "
                    "displays as 'report.pdf', inducing the user to double-click "
                    "and execute malware believing it is a document."
                ),
            )

    # ── R05 ───────────────────────────────────────────────────────
    def rule_R05_macro_office_docs(self) -> None:
        """
        Macro-enabled Office documents (.docm, .xlsm, .xlam, etc.).

        Rationale: Office macro malware is one of the most persistent
        initial-access techniques.  The user is social-engineered to
        click "Enable Content", after which VBA runs arbitrary code.

        Source: filenames (extension check) + t1_has_office_macros flag.
        """
        found = self._files_with_ext(MACRO_EXTENSIONS)
        if found or self.f.get("t1_has_office_macros"):
            evidence = found[:5] if found else ["(flagged by Task-1 extractor)"]
            self._add(
                "R05", "HIGH",
                "Macro-enabled Office documents can execute arbitrary code on open.",
                f"Files: {evidence}",
                rationale=(
                    "VBA macros embedded in Office documents execute under "
                    "full user privileges when 'Enable Content' is clicked. "
                    "This technique remains a top initial-access vector."
                ),
            )

    # ── R06 ───────────────────────────────────────────────────────
    def rule_R06_nested_archives(self) -> None:
        """
        Nested archives inside the archive (AV-evasion technique).

        Rationale: Many AV engines do not recursively extract archives
        beyond a fixed depth.  Attackers nest zip-in-zip structures
        to keep the payload invisible to scanners.

        Source: filenames (extension check) + t1_has_nested_archives
                + max_nested_depth.
        """
        found = self._files_with_ext(ARCHIVE_EXTENSIONS)
        depth = self.f.get("max_nested_depth", 0)
        if found or self.f.get("t1_has_nested_archives"):
            severity = "CRITICAL" if depth >= 3 else "HIGH"
            evidence = found[:5] if found else ["(flagged by Task-1 extractor)"]
            self._add(
                "R06", severity,
                "Nested archives detected — used to evade AV scanning.",
                f"Archives: {evidence}, max nesting depth: {depth}",
                rationale=(
                    "Recursive archives exhaust AV scan budgets; the inner "
                    "payload is never inspected.  Depth ≥ 3 strongly suggests "
                    "intentional evasion."
                ),
            )

    # ── R07 ───────────────────────────────────────────────────────
    def rule_R07_encrypted_with_suspicious_files(self) -> None:
        """
        Encrypted archive containing executables or scripts.

        Rationale: Encryption legitimately protects sensitive data, but
        when combined with executables / scripts it hides payloads from
        every AV or content-inspection tool that cannot supply the
        password.

        Source: is_encrypted + filenames (extension check).
        """
        is_enc = self.f.get("is_encrypted", False)
        suspicious = self._files_with_ext(EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS)

        if is_enc and suspicious:
            self._add(
                "R07", "CRITICAL",
                "Encrypted archive with executables/scripts — payload is hidden from AV.",
                f"Encrypted: True, Suspicious files: {suspicious[:3]}",
                rationale=(
                    "Encryption prevents AV engines from inspecting the "
                    "archive contents.  Combined with executables this is a "
                    "classic payload-delivery evasion pattern."
                ),
            )
        elif is_enc:
            self._add(
                "R07", "LOW",
                "Archive is encrypted — contents cannot be statically scanned.",
                "Encrypted: True (no overtly malicious filenames visible)",
                rationale=(
                    "Encryption alone is not malicious, but it prevents "
                    "automated content inspection."
                ),
            )

    # ── R08 ───────────────────────────────────────────────────────
    def rule_R08_decoy_plus_executable(self) -> None:
        """
        Decoy document + executable combination (classic dropper pattern).

        Rationale: Malware distributors include a legitimate-looking PDF
        or Word document alongside a payload executable.  The decoy opens
        on double-click to avoid user suspicion while the executable
        silently installs malware.

        Source: filenames (extension check) + t1_decoy_and_exe flag.
        """
        decoys = self._files_with_ext(DECOY_EXTENSIONS)
        execs  = self._files_with_ext(EXECUTABLE_EXTENSIONS)
        if (decoys and execs) or self.f.get("t1_decoy_and_exe"):
            self._add(
                "R08", "CRITICAL",
                "Decoy document + executable — classic dropper pattern.",
                f"Decoys: {decoys[:3]}, Executables: {execs[:3]}",
                rationale=(
                    "Pairing a harmless-looking document with an executable "
                    "is the hallmark of a dropper: the victim opens the "
                    "document, sees expected content, and never notices the "
                    "payload that ran in the background."
                ),
            )

    # ── R09 ───────────────────────────────────────────────────────
    def rule_R09_unicode_rtlo(self) -> None:
        """
        Right-to-Left Override character (U+202E) in a filename.

        Rationale: U+202E reverses subsequent characters in the display.
        'evil\u202Eexe.pdf' renders as 'evilfdp.exe' in many file
        managers, hiding the true .exe extension.

        Source: filenames (character scan) + t1_unicode_rtlo flag.
        """
        hits = [fn for fn in self.filenames if has_rtlo(fn)]
        if hits or self.f.get("t1_unicode_rtlo"):
            evidence = hits[:5] if hits else ["(flagged by Task-1 extractor)"]
            self._add(
                "R09", "CRITICAL",
                "RTLO character (U+202E) in filename reverses displayed extension.",
                f"Files: {evidence}",
                rationale=(
                    "The Unicode Right-to-Left Override causes text after it "
                    "to be displayed in reverse.  Attackers craft filenames "
                    "like 'photo\u202Eexe.jpg' which appear as 'photogpj.exe' "
                    "— users see a JPEG icon but click an executable."
                ),
            )

    # ── R10 ───────────────────────────────────────────────────────
    def rule_R10_space_padding(self) -> None:
        """
        Filename stem padded with spaces to obscure the true extension.

        Rationale: 'malware.exe     .pdf' can display as 'malware.exe'
        in narrow file-manager columns, hiding the .pdf decoy suffix
        or vice-versa.

        Source: filenames (stem whitespace check).
        """
        hits = [fn for fn in self.filenames if is_padded_with_spaces(fn)]
        if hits:
            self._add(
                "R10", "HIGH",
                "Filename padded with spaces — hides true extension in file managers.",
                f"Files: {hits[:5]}",
                rationale=(
                    "Long whitespace in file stems pushes the real extension "
                    "out of view in fixed-width columns, tricking users about "
                    "the file type."
                ),
            )

    # ── R11 ───────────────────────────────────────────────────────
    def rule_R11_decompression_bomb(self) -> None:
        """
        Zip-bomb / decompression bomb indicators.

        Rationale: An archive that decompresses to gigabytes of data
        exhausts disk space, RAM, and CPU — disabling AV scanners or
        crashing the target system.  Also used to distract from a
        secondary payload.

        CVE reference: CWE-409 (Improper Handling of Highly Compressed
        Data).  No single CVE covers the generic attack; CVE-2019-9674
        covers Python's zipfile module specifically.

        Source: compression_ratio + total_uncompressed_size
                + t1_archive_bomb flag.
        """
        ratio = self.f.get("compression_ratio", 0.0)
        total = self.f.get("total_uncompressed_size", 0)
        GB    = 1_073_741_824

        if self.f.get("t1_archive_bomb") or (ratio > 100 and total > GB):
            self._add(
                "R11", "CRITICAL",
                "Extreme compression ratio — potential decompression bomb (zip-of-death).",
                f"Ratio: {ratio:.1f}x, Uncompressed: {total / GB:.2f} GB",
                cve="CVE-2019-9674",
                rationale=(
                    "A decompression bomb (CWE-409) stores gigabytes or "
                    "petabytes of data in a tiny file.  Extracting it exhausts "
                    "disk/RAM and can crash or disable antivirus engines, "
                    "creating an opening for secondary payloads. "
                    "CVE-2019-9674 covers this class of attack in Python's "
                    "zipfile module."
                ),
            )
        elif ratio > 50:
            self._add(
                "R11", "HIGH",
                "Very high compression ratio — possible zip-bomb or heavily packed payload.",
                f"Ratio: {ratio:.1f}x",
                cve="CVE-2019-9674",
                rationale=(
                    "Compression ratios above 50:1 are unusual for standard "
                    "files.  Legitimate data rarely compresses above 10:1 "
                    "unless it is already compressed media."
                ),
            )

    # ── R12 ───────────────────────────────────────────────────────
    def rule_R12_excessive_file_count(self) -> None:
        """
        Extremely high file count — zip-bomb variant or resource exhaustion.

        Rationale: Archives with thousands of entries stress-test AV scan
        loops and file-system quotas.  Some antivirus tools give up after
        a fixed entry count, leaving the rest uninspected.

        CVE-2021-35517: Apache Commons Compress OOM via crafted TAR.

        Source: file_count (from archive metadata).
        """
        count = self.f.get("file_count", len(self.files))

        if count > 10_000:
            self._add(
                "R12", "HIGH",
                "Extremely high file count — may exhaust AV scan budgets or system resources.",
                f"File count: {count:,}",
                cve="CVE-2021-35517",
                rationale=(
                    "Archives with 10,000+ entries can overwhelm AV engines "
                    "that limit per-archive scan iterations, leaving later "
                    "entries uninspected."
                ),
            )
        elif count > 1_000:
            self._add(
                "R12", "MEDIUM",
                "Unusually high file count — atypical for standard archives.",
                f"File count: {count:,}",
                rationale=(
                    "Most legitimate archives contain fewer than 1,000 files. "
                    "Counts above this threshold warrant inspection."
                ),
            )

    # ── R13 ───────────────────────────────────────────────────────
    def rule_R13_path_traversal(self) -> None:
        """
        Path-traversal filenames (Zip Slip attack).

        Rationale: An archive entry named '../../Windows/System32/evil.dll'
        extracts outside the target directory when the application fails
        to sanitize paths, overwriting system files or dropping backdoors.

        CVE-2018-1000544: Zip Slip in Ruby's rubyzip gem (representative
        of the entire Zip Slip class — Snyk reports 100+ affected libraries).

        Source: filenames (.. or leading / check).
        """
        hits = [
            fn for fn in self.filenames
            if ".." in fn or fn.startswith("/") or fn.startswith("\\")
        ]
        if hits:
            self._add(
                "R13", "CRITICAL",
                "Path-traversal filenames (Zip Slip) — can overwrite arbitrary files on extraction.",
                f"Files: {hits[:5]}",
                cve="CVE-2018-1000544",
                rationale=(
                    "Zip Slip (CVE-2018-1000544 and >100 related library CVEs) "
                    "allows '..' sequences in archive entry names to escape the "
                    "extraction directory, overwriting system files or dropping "
                    "persistence backdoors."
                ),
            )

    # ── R14 ───────────────────────────────────────────────────────
    def rule_R14_null_byte_filename(self) -> None:
        """
        Null byte (\\x00) in a filename — parser confusion attack.

        Rationale: Many languages (C, PHP) treat \\x00 as string
        termination.  'evil.exe\\x00.pdf' may pass an extension check
        that compares the suffix after \\x00, while the OS sees 'evil.exe'.

        CVE-2008-5518: Apache Tomcat null-byte file-upload bypass.

        Source: filenames (null byte character scan).
        """
        hits = [fn for fn in self.filenames if "\x00" in fn]
        if hits:
            self._add(
                "R14", "CRITICAL",
                "Null byte in filename — bypasses extension checks in vulnerable parsers.",
                f"Files: {hits[:3]}",
                cve="CVE-2008-5518",
                rationale=(
                    "A null byte in a filename terminates the string in C-based "
                    "parsers.  'evil.exe\\x00.pdf' can fool a validator checking "
                    "the extension after \\x00, while the OS interprets the name "
                    "as 'evil.exe'."
                ),
            )

    # ── R15 ───────────────────────────────────────────────────────
    def rule_R15_downloader_strings(self) -> None:
        """
        Download-command keywords in extracted strings.

        Rationale: Scripts inside archives that call Invoke-WebRequest,
        BITSAdmin, certutil, or curl are characteristic of staged malware
        delivery, where the archive contains only a thin downloader that
        fetches the real payload post-execution.

        Source: extracted_strings (urls_found + suspicious_commands).
        """
        found = contains_keyword(self._strings_blob(), DOWNLOADER_KEYWORDS)
        if found:
            self._add(
                "R15", "CRITICAL",
                "Download-command keywords in strings — indicates staged malware delivery.",
                f"Keywords: {found}",
                rationale=(
                    "Commands like Invoke-WebRequest, certutil -decode, or "
                    "BITSAdmin are used by loaders to fetch a second-stage "
                    "payload after the archive is extracted and executed."
                ),
            )

    # ── R16 ───────────────────────────────────────────────────────
    def rule_R16_execution_strings(self) -> None:
        """
        Shell / process-execution API references in extracted strings.

        Rationale: References to WScript.Shell, cmd.exe, CreateProcess,
        or VirtualAlloc inside archive content indicate a script or binary
        that will spawn processes or inject code.

        Source: extracted_strings.
        """
        found = contains_keyword(self._strings_blob(), EXECUTION_KEYWORDS)
        if found:
            self._add(
                "R16", "HIGH",
                "Shell-execution API references in strings — possible malicious script.",
                f"Keywords: {found}",
                rationale=(
                    "WScript.Shell, CreateProcess, VirtualAlloc and similar "
                    "APIs are core primitives for process spawning and code "
                    "injection used by malware."
                ),
            )

    # ── R17 ───────────────────────────────────────────────────────
    def rule_R17_obfuscation_strings(self) -> None:
        """
        Obfuscation-technique keywords in extracted strings.

        Rationale: Base64 encoding, -EncodedCommand, IEX(), and similar
        patterns are used to hide malicious PowerShell or VBS from static
        string-matching tools.

        Source: extracted_strings.
        """
        found = contains_keyword(self._strings_blob(), OBFUSCATION_KEYWORDS)
        if found:
            self._add(
                "R17", "HIGH",
                "Obfuscation techniques in strings — attacker hiding payload from static analysis.",
                f"Keywords: {found}",
                rationale=(
                    "Base64 encoding, -EncodedCommand, and Invoke-Expression "
                    "are standard PowerShell obfuscation primitives; they "
                    "conceal the true command from signature-based detection."
                ),
            )

    # ── R18 ───────────────────────────────────────────────────────
    def rule_R18_high_entropy_files(self) -> None:
        """
        High-entropy files (entropy ≥ 7.5 bits/byte).

        Rationale: Encrypted or packed executables have near-random byte
        distributions (entropy close to 8.0).  Normal text, source code,
        and uncompressed binary data have much lower entropy.  Files with
        high entropy that are NOT natively compressed formats (JPEG, PNG,
        ZIP) are likely packed or encrypted payloads.

        Source: files[].entropy.
        """
        safe_exts = {".zip", ".gz", ".bz2", ".7z", ".jpg", ".jpeg",
                     ".png", ".gif", ".mp3", ".mp4", ".rar"}
        hits = [
            fi["name"] for fi in self.files
            if fi.get("entropy", 0.0) >= 7.5
            and get_extension(fi.get("name", "")) not in safe_exts
        ]
        if hits:
            self._add(
                "R18", "HIGH",
                "High-entropy files (≥ 7.5 bits/byte) — likely packed or encrypted payloads.",
                f"Files: {hits[:5]}",
                rationale=(
                    "A Shannon entropy of ≥ 7.5 bits/byte indicates near-random "
                    "data, consistent with encrypted or UPX/MPRESS-packed "
                    "executables.  Legitimate plain-text files score 4–6."
                ),
            )

    # ── R19 ───────────────────────────────────────────────────────
    def rule_R19_suspicious_dirs_and_hidden(self) -> None:
        """
        Suspicious directory names, hidden files, or flagged filenames.

        Rationale: Targeting system directories like %AppData%\\Roaming,
        Startup, or System32 via archive paths attempts to drop
        persistence or system-altering files to sensitive locations.

        Source: files[].is_directory + files[].name + files[].is_hidden
                + t1_suspicious_filenames.
        """
        dirs = [fi.get("name", "") for fi in self.files if fi.get("is_directory")]
        dir_hits = [
            d for d in dirs
            if any(kw in d.lower() for kw in SUSPICIOUS_DIRNAMES)
        ]

        hidden_hits = [fi.get("name", "") for fi in self.files if fi.get("is_hidden")]

        t1_extra = [
            s for s in self.f.get("t1_suspicious_filenames", [])
            if s not in dir_hits and s not in hidden_hits
        ]

        all_hits = dir_hits + hidden_hits + t1_extra
        if all_hits:
            self._add(
                "R19", "MEDIUM",
                "Suspicious directory names, hidden files, or flagged filenames detected.",
                f"Dirs: {dir_hits[:3]}, Hidden: {hidden_hits[:3]}, Other: {t1_extra[:3]}",
                rationale=(
                    "Archive entries targeting system paths (AppData, Startup, "
                    "System32) or marked hidden attempt to drop files in "
                    "persistence locations invisible to the user."
                ),
            )

    # ── R20 ───────────────────────────────────────────────────────
    def rule_R20_phishing_keywords(self) -> None:
        """
        Phishing-related keywords in filenames.

        Rationale: Social-engineering attacks name files 'Invoice_Q3.exe'
        or 'URGENT_Payment.pdf.bat' to create urgency and lure victims.

        Source: filenames.
        """
        hits = [
            fn for fn in self.filenames
            if any(kw in fn.lower() for kw in PHISHING_KEYWORDS)
        ]
        if hits:
            self._add(
                "R20", "MEDIUM",
                "Phishing-related terms in filenames — social-engineering lure.",
                f"Files: {hits[:5]}",
                rationale=(
                    "Terms like 'invoice', 'payment', 'urgent', or 'verify' "
                    "exploit psychological urgency to induce users to open "
                    "archive contents without scrutiny."
                ),
            )

    # ── R21 ───────────────────────────────────────────────────────
    def rule_R21_winrar_cve_2023_38831(self) -> None:
        """
        CVE-2023-38831: WinRAR arbitrary code execution via crafted ZIP.

        HOW IT WORKS: A ZIP contains a benign file (e.g. 'report.pdf')
        AND a folder with the EXACT same name ('report.pdf/').  When the
        user double-clicks the benign file, WinRAR also processes the
        same-named folder's contents (including executables), triggering
        silent code execution.

        Detection: ZIP format + (decoy extension file AND same-named
        directory entry) or Task-1 decoy_and_exe flag.

        Source: archive_format + files (name collision check)
                + t1_decoy_and_exe flag.
        """
        fmt = self.f.get("archive_format", "").lower()
        if fmt not in ("zip",):
            return

        # Collect all base names regardless of trailing slash
        base_names: dict[str, list[str]] = {}
        for fn in self.filenames:
            base = Path(fn).name.rstrip("/\\")
            base_names.setdefault(base, []).append(fn)

        # A collision exists when a file name == a directory name
        dir_names  = {Path(fi.get("name","")).name for fi in self.files if fi.get("is_directory")}
        file_names = {Path(fi.get("name","")).name for fi in self.files if not fi.get("is_directory")}
        collisions = [
            name for name in dir_names & file_names
            if get_extension(name) in DECOY_EXTENSIONS
        ]

        has_exe = bool(self._files_with_ext(EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS))

        if (collisions and has_exe) or (self.f.get("t1_decoy_and_exe") and fmt == "zip"):
            self._add(
                "R21", "CRITICAL",
                "CVE-2023-38831 pattern: ZIP with same-named file+folder containing executable.",
                f"Format: ZIP, Name collisions: {collisions[:3]}, Executables present.",
                cve="CVE-2023-38831",
                rationale=(
                    "CVE-2023-38831 is a WinRAR logical flaw: when the user "
                    "clicks a benign file, WinRAR also extracts and runs "
                    "executables inside a same-named folder, achieving silent "
                    "RCE.  Actively exploited by APT28, Sandworm, and others."
                ),
            )

    # ── R22 ───────────────────────────────────────────────────────
    def rule_R22_winrar_buffer_overflow_2018(self) -> None:
        """
        CVE-2018-18384: WinRAR 5.x stack-based buffer overflow.

        A specially crafted RAR or ZIP archive with a long filename
        (>260 characters) overflows a stack buffer in the parsing code,
        allowing arbitrary code execution.

        Source: archive_format + filenames (long name check)
                + is_corrupted.
        """
        fmt      = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        long_paths = [fn for fn in self.filenames if len(fn) > 260]

        if fmt in ("rar", "zip") and (is_corrupt or long_paths):
            self._add(
                "R22", "HIGH",
                "CVE-2018-18384: Long filename or malformed RAR/ZIP may trigger stack buffer overflow.",
                f"Format: {fmt.upper()}, Corrupted: {is_corrupt}, "
                f"Long paths (>260 chars): {long_paths[:3]}",
                cve="CVE-2018-18384",
                rationale=(
                    "CVE-2018-18384 is a stack buffer overflow in WinRAR 5.x "
                    "triggered by archive entries with filenames longer than "
                    "260 characters, leading to arbitrary code execution."
                ),
            )

    # ── R23 ───────────────────────────────────────────────────────
    def rule_R23_infozip_long_comment(self) -> None:
        """
        CVE-2016-9844: Info-ZIP unzip buffer overflow via long comment.

        A ZIP archive with a comment field longer than 512 bytes can
        overflow a fixed-size buffer in unzip < 6.0 patch 11,
        leading to a crash or possible code execution.

        Source: archive_format + archive_comment length.
        """
        fmt         = self.f.get("archive_format", "").lower()
        comment_len = len(self.f.get("archive_comment", ""))

        if fmt == "zip" and comment_len > 512:
            self._add(
                "R23", "HIGH",
                "CVE-2016-9844: Excessively long ZIP comment may trigger Info-ZIP buffer overflow.",
                f"Comment length: {comment_len} bytes",
                cve="CVE-2016-9844",
                rationale=(
                    "Info-ZIP unzip (< 6.0p11) uses a fixed 512-byte buffer "
                    "for archive comments.  A comment exceeding this causes a "
                    "stack overflow, potentially allowing code execution on "
                    "systems running the vulnerable version."
                ),
            )

    # ── R24 ───────────────────────────────────────────────────────
    def rule_R24_unicode_normalization_spoof(self) -> None:
        """
        Unicode homograph / normalization spoofing with executable extension.

        Rationale: Non-ASCII Unicode characters that look like ASCII
        letters (homoglyphs) or characters that normalize differently
        across OS/application pairs can fool filename validators.
        E.g. a Cyrillic 'а' (U+0430) looks identical to Latin 'a'.

        Source: filenames (non-ASCII char + executable extension check).
        """
        hits = [
            fn for fn in self.filenames
            if has_non_ascii_exec(fn, EXECUTABLE_EXTENSIONS)
        ]
        if hits:
            self._add(
                "R24", "CRITICAL",
                "Unicode homograph in executable filename — may fool validators and users.",
                f"Files: {hits[:5]}",
                rationale=(
                    "Lookalike Unicode characters (Cyrillic, fullwidth, etc.) "
                    "render identically to ASCII in most fonts.  Combined with "
                    "an executable extension this can bypass allowlists and "
                    "deceive users about the file type."
                ),
            )

    # ── R25 ───────────────────────────────────────────────────────
    def rule_R25_corrupted_archive(self) -> None:
        """
        Corrupted or malformed archive structure.

        Rationale: Attackers intentionally corrupt archive headers to
        (a) evade automated scanners that bail on parse errors, or
        (b) trigger parser vulnerabilities leading to memory corruption.

        CVE-2016-1541: libarchive heap-based buffer overflow in ZIP
        handling when processing crafted / malformed entries.

        Source: is_corrupted flag.
        """
        if self.f.get("is_corrupted"):
            self._add(
                "R25", "MEDIUM",
                "Corrupted/malformed archive — may evade scanners or exploit vulnerable parsers.",
                "is_corrupted: True",
                cve="CVE-2016-1541",
                rationale=(
                    "Malformed archives can crash AV engines (evasion) or "
                    "trigger memory-corruption bugs in parsers "
                    "(CVE-2016-1541 — libarchive heap overflow in malformed ZIP)."
                ),
            )

    # ── R26 ───────────────────────────────────────────────────────
    def rule_R26_split_archive(self) -> None:
        """
        Split archive detected.

        Rationale: Multi-part archives (.part1.rar, .z01, etc.) must be
        reassembled before the payload is accessible.  This means static
        scanning of individual parts is ineffective — the real payload
        only exists after reassembly.

        CVE-2005-2349: WinRAR split archive handling flaw.

        Source: is_split flag.
        """
        if self.f.get("is_split"):
            self._add(
                "R26", "MEDIUM",
                "Split archive — payload only visible after reassembly; parts evade scanning.",
                "is_split: True",
                cve="CVE-2005-2349",
                rationale=(
                    "Static scanners analyzing individual archive parts see "
                    "only fragments.  Reassembly produces the full payload, "
                    "which may differ entirely from any individual part."
                ),
            )

    # ── R27 ───────────────────────────────────────────────────────
    def rule_R27_size_metadata_trick(self) -> None:
        """
        Zero uncompressed size but non-zero compressed size — header forgery.

        Rationale: Manipulating the uncompressed-size field to zero while
        the data block is non-empty is a known trick to hide real content
        from tools that rely on the header value for quick-look decisions.

        Source: files[].compressed_size + files[].uncompressed_size.
        """
        hits = [
            fi.get("name", "unknown") for fi in self.files
            if fi.get("uncompressed_size", 1) == 0
            and fi.get("compressed_size", 0) > 0
        ]
        if hits:
            self._add(
                "R27", "HIGH",
                "Files with zero uncompressed size but non-zero compressed size — header forgery.",
                f"Files: {hits[:5]}",
                rationale=(
                    "Forging the uncompressed-size field to 0 hides real "
                    "content from tools that read header metadata for quick "
                    "classification instead of fully decompressing entries."
                ),
            )

    # ── R28 ───────────────────────────────────────────────────────
    def rule_R28_timestamp_anomaly(self) -> None:
        """
        Impossible or anomalous file timestamps (anti-forensics).

        ZIP format stores timestamps with year ≥ 1980.  Years before 1980
        or far in the future (> current year + 2) indicate either
        deliberate tampering to confuse timeline analysis or
        exploitation of timestamp-parsing vulnerabilities.

        CVE-2008-0888: WinZip timestamp handling crash.

        Source: files[].timestamp.
        """
        current_year = datetime.now().year
        hits: list[tuple[str, str]] = []

        for fi in self.files:
            ts = fi.get("timestamp", "")
            if ts:
                m = _YEAR_RE.search(ts)
                if m:
                    year = int(m.group(1))
                    if year < 1980 or year > current_year + 2:
                        hits.append((fi.get("name", "?"), ts))

        if hits:
            self._add(
                "R28", "LOW",
                "Anomalous file timestamps — possible anti-forensics tampering.",
                f"Files: {hits[:3]}",
                cve="CVE-2008-0888",
                rationale=(
                    "ZIP timestamps must be ≥ 1980 by specification.  Values "
                    "outside the valid range indicate deliberate manipulation "
                    "to disrupt forensic timeline reconstruction."
                ),
            )

    # ── R29 ───────────────────────────────────────────────────────
    def rule_R29_hardcoded_urls(self) -> None:
        """
        Hardcoded URLs or IP addresses in extracted strings.

        Rationale: Hardcoded network addresses in scripts or binaries
        indicate C2 (command-and-control) communication channels or
        staged-download sources.  Even a single URL pointing to a
        suspicious TLD or IP in a non-CDN range is significant.

        Note: No single CVE maps to this generic indicator; URLs are
        a behavioural IOC reported across many malware families.

        Source: extracted_strings (urls_found + suspicious_commands).
        """
        found_urls: list[str] = []
        for s in self.strings:
            for m in _URL_RE.finditer(s):
                url = m.group(0)
                if url not in found_urls:
                    found_urls.append(url)

        if found_urls:
            sev = "HIGH" if len(found_urls) > 3 else "MEDIUM"
            self._add(
                "R29", sev,
                "Hardcoded URLs/IPs in strings — possible C2 channel or staged download.",
                f"URLs/IPs: {found_urls[:5]}",
                rationale=(
                    "Hardcoded network addresses inside archive content "
                    "indicate the extracted payload will phone home or pull "
                    "a second stage from an attacker-controlled server."
                ),
            )

    # ── R30 ───────────────────────────────────────────────────────
    def rule_R30_mime_extension_mismatch(self) -> None:
        """
        File extension does not match detected MIME type — disguised executable.

        Rationale: A file named 'document.pdf' that is actually a PE
        binary (MIME: application/x-dosexec) is a classic disguise.
        The discrepancy can only be detected by inspecting magic bytes,
        not the filename.

        CVE-2012-0010: IE content-type mismatch leading to code execution.

        Source: files[].detected_mime + files[].name
                + t1_extension_mismatches list.
        """
        own: list[str] = []
        for fi in self.files:
            ext  = get_extension(fi.get("name", ""))
            mime = fi.get("detected_mime", "").lower()
            if not ext or not mime:
                continue
            # PE binary disguised as document / image
            if mime in ("application/x-dosexec", "application/x-msdownload"):
                if ext not in EXECUTABLE_EXTENSIONS:
                    own.append(fi.get("name"))
            # PDF with wrong MIME
            elif ext == ".pdf" and "pdf" not in mime:
                own.append(fi.get("name"))
            # JPEG with wrong MIME
            elif ext in {".jpg", ".jpeg"} and "jpeg" not in mime and "image" not in mime:
                own.append(fi.get("name"))

        all_hits = list(set(filter(None, own + self.f.get("t1_extension_mismatches", []))))
        if all_hits:
            self._add(
                "R30", "HIGH",
                "MIME type does not match file extension — likely disguised executable.",
                f"Files: {all_hits[:5]}",
                cve="CVE-2012-0010",
                rationale=(
                    "Magic-byte inspection reveals the true file type regardless "
                    "of the extension.  A .pdf that is actually a PE binary "
                    "is a textbook executable-in-disguise delivery technique."
                ),
            )

    # ── R31 ───────────────────────────────────────────────────────
    def rule_R31_oversized_archive(self) -> None:
        """
        Archive size exceeds 2 GB — resource exhaustion or content burial.

        Rationale: Very large archives can overwhelm analysis tools with
        memory/time limits or bury malicious files among vast amounts of
        legitimate-looking content.

        Source: file_size.
        """
        size = self.f.get("file_size", 0)
        GB   = 1_073_741_824

        if size > 2 * GB:
            self._add(
                "R31", "MEDIUM",
                "Archive exceeds 2 GB — may overwhelm analysis tools or hide content.",
                f"Size: {size / GB:.2f} GB",
                rationale=(
                    "Oversized archives push many AV and sandbox tools past "
                    "their scan-size limits, causing them to skip the file "
                    "entirely.  Malicious files buried at the end of a giant "
                    "archive may never be inspected."
                ),
            )

    # ── R32 ───────────────────────────────────────────────────────
    def rule_R32_winrar_ace_path_traversal(self) -> None:
        """
        CVE-2018-20250: WinRAR ACE format absolute path traversal RCE.

        UNACEV2.DLL (a 19-year-old third-party DLL bundled with WinRAR)
        ignores the extraction destination when the ACE filename field
        contains absolute paths.  Attackers drop executables directly
        into %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
        for persistence on next reboot — no privilege escalation needed.

        Detection heuristic: filename starts with 'C:\\' (or other
        drive letter), '\\', or contains 'Startup'.

        Source: filenames (absolute-path check) + presence of executables.
        """
        has_abs = any(
            re.match(r"^[A-Za-z]:\\", fn)
            or fn.startswith("\\\\")
            or "Startup" in fn
            or "startup" in fn.lower()
            for fn in self.filenames
        )
        has_exe = bool(self._files_with_ext(
            {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"}
        ))
        fmt = self.f.get("archive_format", "").lower()

        if has_abs and has_exe:
            self._add(
                "R32", "CRITICAL",
                "CVE-2018-20250: Absolute path in archive entry — WinRAR ACE path traversal RCE.",
                f"Format: {fmt.upper()}, Absolute paths + executables detected.",
                cve="CVE-2018-20250",
                rationale=(
                    "CVE-2018-20250 allows ACE archives to write files to "
                    "arbitrary absolute paths (including the Startup folder) "
                    "via UNACEV2.DLL path-validation bypass.  File persists "
                    "and executes on next user logon without privilege "
                    "escalation.  Exploited in the wild by multiple APT groups."
                ),
            )

    # ── R33 ───────────────────────────────────────────────────────
    def rule_R33_winrar_oob_write(self) -> None:
        """
        CVE-2018-20252 / CVE-2018-20253: WinRAR out-of-bounds write.

        Crafted ACE or RAR archives trigger out-of-bounds write
        vulnerabilities during parsing, leading to memory corruption
        and potential arbitrary code execution.

        Source: is_corrupted + archive_format.
        """
        fmt        = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)

        if fmt in ("rar", "ace") and is_corrupt:
            self._add(
                "R33", "HIGH",
                "CVE-2018-20252/20253: Corrupted RAR/ACE may trigger out-of-bounds write.",
                f"Format: {fmt.upper()}, Corrupted: True",
                cve="CVE-2018-20252",
                rationale=(
                    "CVE-2018-20252 and CVE-2018-20253 are OOB write bugs "
                    "in WinRAR triggered during parsing of malformed ACE/RAR "
                    "archives, potentially resulting in arbitrary code execution."
                ),
            )

    # ── R34 ───────────────────────────────────────────────────────
    def rule_R34_python_tarfile_traversal(self) -> None:
        """
        CVE-2007-4559: Python tarfile module path traversal.

        Python's tarfile.extract() / extractall() does not sanitize
        member names.  An entry named '../../evil' extracts outside the
        target directory when the application uses the vulnerable API.
        This bug remained unfixed for 15 years (patched in 3.12).

        Source: archive_format (tar) + path-traversal filenames.
        """
        fmt  = self.f.get("archive_format", "").lower()
        hits = [
            fn for fn in self.filenames
            if ".." in fn or fn.startswith("/")
        ]
        if fmt in ("tar", "tgz", "tbz2", "gz") and hits:
            self._add(
                "R34", "HIGH",
                "CVE-2007-4559: TAR archive with path-traversal entries — Python tarfile unsafe extraction.",
                f"Files: {hits[:5]}",
                cve="CVE-2007-4559",
                rationale=(
                    "CVE-2007-4559: Python's tarfile.extractall() does not "
                    "filter '..' path components.  Applications using this API "
                    "without manual path validation allow archive entries to "
                    "overwrite arbitrary files outside the extraction directory."
                ),
            )

    # ── R35 ───────────────────────────────────────────────────────
    def rule_R35_7zip_symlink_traversal(self) -> None:
        """
        CVE-2025-11001 / CVE-2025-11002: 7-Zip symbolic-link path traversal in ZIP.

        Crafted ZIP files contain symbolic links whose targets point
        outside the extraction directory.  7-Zip < 25.00 follows the
        symlinks without validation, writing subsequent archive entries
        to arbitrary filesystem locations — potentially achieving RCE
        by dropping files in auto-run locations.

        Source: archive_format (zip) + path-traversal / symlink-like entries.
        """
        fmt         = self.f.get("archive_format", "").lower()
        has_traversal = any(
            ".." in fn or fn.startswith("/") or fn.startswith("\\")
            for fn in self.filenames
        )
        if fmt == "zip" and has_traversal:
            self._add(
                "R35", "CRITICAL",
                "CVE-2025-11001/11002: ZIP with traversal/symlink entries — 7-Zip RCE vector.",
                "Traversal paths detected in ZIP archive.",
                cve="CVE-2025-11001",
                rationale=(
                    "CVE-2025-11001 and CVE-2025-11002 affect 7-Zip < 25.00: "
                    "symlinks embedded in ZIP archives can escape the extraction "
                    "directory, enabling arbitrary file write and subsequent "
                    "RCE (e.g. via Startup folder persistence)."
                ),
            )

    # ── R36 ───────────────────────────────────────────────────────
    def rule_R36_7zip_rar5_heap_overflow(self) -> None:
        """
        CVE-2025-53816: 7-Zip heap-buffer overflow in RAR5 decoder.

        A miscalculation in the rem value inside NCompress::NRar5::CDecoder
        causes zeroes to be written past the allocated heap buffer when
        recovering from corrupted RAR5 data — resulting in memory
        corruption and DoS.  RCE is not confirmed but theoretically
        possible depending on heap layout.

        CVSS: 5.5 (Medium).  Severity here is MEDIUM accordingly.

        Source: archive_format (rar) + is_corrupted.
        """
        fmt        = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)

        if fmt == "rar" and is_corrupt:
            self._add(
                "R36", "MEDIUM",
                "CVE-2025-53816: Corrupted RAR5 may trigger 7-Zip heap buffer overflow (DoS).",
                "Format: RAR, Corrupted: True",
                cve="CVE-2025-53816",
                rationale=(
                    "CVE-2025-53816 (CVSS 5.5) is a heap OOB write in "
                    "7-Zip's RAR5 decoder triggered by malformed recovery "
                    "data.  The immediate impact is DoS; memory-layout "
                    "conditions may allow further exploitation."
                ),
            )

    # ── R37 ───────────────────────────────────────────────────────
    def rule_R37_libarchive_rar_oob(self) -> None:
        """
        CVE-2024-48957: libarchive out-of-bounds read in RAR execute_filter_audio.

        A specially crafted RAR archive triggers an OOB read in the
        execute_filter_audio function of libarchive's RAR support,
        causing memory corruption and potential information leakage.

        Source: archive_format (rar) + is_corrupted.
        """
        fmt        = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)

        if fmt == "rar" and is_corrupt:
            self._add(
                "R37", "HIGH",
                "CVE-2024-48957: Crafted RAR may trigger libarchive OOB read in audio filter.",
                "Format: RAR, Corrupted: True",
                cve="CVE-2024-48957",
                rationale=(
                    "CVE-2024-48957 is an OOB read in libarchive's RAR audio "
                    "filter.  Exploiting it via a malformed archive can leak "
                    "memory contents and may allow further exploitation."
                ),
            )

    # ── R38 ───────────────────────────────────────────────────────
    def rule_R38_libarchive_windows_rce(self) -> None:
        """
        CVE-2024-20696: libarchive RCE on Windows via malformed archive.

        Windows 10+ integrates libarchive into Explorer for transparent
        ZIP/TAR/CAB handling.  Opening a crafted archive with a
        malformed/oversized filename can corrupt heap memory and
        execute arbitrary code under the logged-in user context.
        No special software required — double-clicking the file
        in Explorer is sufficient.

        Source: archive_format (zip/tar/cab) + (is_corrupted OR long filenames).
        """
        fmt        = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        long_paths = [fn for fn in self.filenames if len(fn) > 200]

        if fmt in ("zip", "tar", "cab") and (is_corrupt or long_paths):
            self._add(
                "R38", "CRITICAL",
                "CVE-2024-20696: Malformed archive may trigger libarchive Windows RCE via Explorer.",
                f"Format: {fmt.upper()}, Corrupted: {is_corrupt}, "
                f"Long filenames (>200): {long_paths[:3]}",
                cve="CVE-2024-20696",
                rationale=(
                    "CVE-2024-20696 targets libarchive integrated into Windows "
                    "Explorer.  A double-click on a crafted ZIP/TAR/CAB triggers "
                    "heap corruption and RCE under the current user, with zero "
                    "additional software required."
                ),
            )

    # ── R39 ───────────────────────────────────────────────────────
    def rule_R39_winrar_ntfs_ads(self) -> None:
        """
        CVE-2025-8088: WinRAR path traversal via NTFS Alternate Data Streams.
        CVE-2025-6218: WinRAR classic directory traversal via crafted paths.

        CVE-2025-8088 (exploited by RomCom / Sandworm): The ADS handling
        path in WinRAR < 7.13 does not fully normalize extraction paths
        when an archive entry uses ':' (ADS notation).  Attackers craft
        entries like 'decoy.txt:payload.exe' which escape the extraction
        directory and can reach auto-start locations.

        CVE-2025-6218: A separate WinRAR path-normalization flaw where
        spaces after '..' in intermediate path segments are mishandled,
        allowing directory traversal with a different bypass technique.

        Detection: archive entries containing ':' (ADS) not prefixed by
        a drive letter, OR '..' traversal sequences.

        Source: filenames (colon/traversal check).
        """
        ads_hits      = [fn for fn in self.filenames if ":" in fn and not re.match(r"^[A-Za-z]:", fn)]
        traversal_hits = [fn for fn in self.filenames if ".." in fn]
        all_hits = list(set(ads_hits + traversal_hits))

        if all_hits:
            # ADS entries specifically map to CVE-2025-8088
            primary_cve = "CVE-2025-8088" if ads_hits else "CVE-2025-6218"
            self._add(
                "R39", "CRITICAL",
                f"NTFS ADS / path-traversal in filenames — {primary_cve} WinRAR RCE vector.",
                f"ADS entries: {ads_hits[:3]}, Traversal: {traversal_hits[:3]}",
                cve=primary_cve,
                rationale=(
                    "CVE-2025-8088 (RomCom zero-day): ADS-notation archive "
                    "entries bypass WinRAR path validation, silently writing "
                    "payloads to Startup or other auto-run locations. "
                    "CVE-2025-6218 achieves the same via space-padded '..' "
                    "segments.  Both were exploited in the wild in 2025."
                ),
            )

    # ── R40 ───────────────────────────────────────────────────────
    def rule_R40_libarchive_double_free(self) -> None:
        """
        CVE-2019-18408: libarchive use-after-free / double-free in RAR decoder.

        A crafted RAR archive triggers a double-free in
        parse_codes() of libarchive's RAR support.  The bug can
        cause memory corruption, crash, or potentially allow code
        execution depending on allocator behaviour.

        Source: archive_format (rar) + is_corrupted.
        """
        fmt        = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)

        if fmt == "rar" and is_corrupt:
            self._add(
                "R40", "HIGH",
                "CVE-2019-18408: Crafted RAR may trigger libarchive double-free / memory corruption.",
                "Format: RAR, Corrupted: True",
                cve="CVE-2019-18408",
                rationale=(
                    "CVE-2019-18408 is a double-free in libarchive's RAR "
                    "parse_codes() function triggered by malformed archive "
                    "data.  Memory corruption from double-free can lead to "
                    "denial of service or arbitrary code execution."
                ),
            )

    # ── R41 ───────────────────────────────────────────────────────
    def rule_R41_infozip_crc_overflow(self) -> None:
        """
        CVE-2014-8139 / CVE-2014-8140: Info-ZIP unzip CRC and extra-field
        buffer overflows.

        Crafted ZIP files with malformed CRC32 values or oversized extra
        fields trigger stack/heap buffer overflows in unzip < 6.0 patch 11.
        An attacker who can supply a ZIP to a system running the vulnerable
        version achieves code execution.

        Source: archive_format (zip) + (is_corrupted OR long comment).
        """
        fmt        = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        comment_len = len(self.f.get("archive_comment", ""))

        if fmt == "zip" and (is_corrupt or comment_len > 256):
            self._add(
                "R41", "HIGH",
                "CVE-2014-8139/8140: Malformed ZIP may trigger Info-ZIP CRC/extra-field overflow.",
                f"Corrupted: {is_corrupt}, Comment length: {comment_len}",
                cve="CVE-2014-8139",
                rationale=(
                    "CVE-2014-8139 (CRC overflow) and CVE-2014-8140 (extra-field "
                    "overflow) in Info-ZIP unzip < 6.0p11 allow a crafted ZIP "
                    "to smash the stack and execute arbitrary code."
                ),
            )

    # ── R42 ───────────────────────────────────────────────────────
    def rule_R42_commons_compress_oom(self) -> None:
        """
        CVE-2021-36090 / CVE-2021-35517: Apache Commons Compress OOM via
        crafted ZIP or TAR archive.

        When reading specially crafted ZIP (CVE-2021-36090) or TAR
        (CVE-2021-35517) archives, Commons Compress can be made to
        allocate enormous amounts of memory even for tiny inputs,
        causing OutOfMemoryError in any Java application that uses the
        library for archive extraction.

        Thresholds: compression_ratio > 50 or file_count > 500 for ZIP;
        analogous for TAR.

        Source: archive_format + compression_ratio + file_count.
        """
        fmt   = self.f.get("archive_format", "").lower()
        ratio = self.f.get("compression_ratio", 0.0)
        count = self.f.get("file_count", 0)

        # ZIP variant → CVE-2021-36090
        if fmt == "zip" and (ratio > 50 or count > 500):
            self._add(
                "R42", "MEDIUM",
                "CVE-2021-36090: High compression/file-count ZIP may cause Commons Compress OOM.",
                f"Ratio: {ratio:.1f}x, File count: {count:,}",
                cve="CVE-2021-36090",
                rationale=(
                    "CVE-2021-36090: Apache Commons Compress 1.0–1.20 allocates "
                    "memory proportional to claimed (uncompressed) sizes in ZIP "
                    "entries.  A crafted archive with huge claimed sizes causes "
                    "OOM even for very small compressed inputs, crashing any "
                    "Java service that processes the file."
                ),
            )
        # TAR variant → CVE-2021-35517
        elif fmt in ("tar", "tgz", "tbz2") and (ratio > 50 or count > 500):
            self._add(
                "R42", "MEDIUM",
                "CVE-2021-35517: High compression/file-count TAR may cause Commons Compress OOM.",
                f"Ratio: {ratio:.1f}x, File count: {count:,}",
                cve="CVE-2021-35517",
                rationale=(
                    "CVE-2021-35517: Apache Commons Compress 1.0–1.20 TAR "
                    "handling can be forced into excessive memory allocation "
                    "via a crafted TAR, causing DoS for Java services."
                ),
            )

    # ── R43 ───────────────────────────────────────────────────────
    def rule_R43_p7zip_heap_overflow(self) -> None:
        """
        CVE-2022-29072: p7zip / 7-Zip heap buffer overflow via crafted ZIP.

        NArchive::NZip::CInArchive::FindCd performs out-of-bounds memory
        access when parsing malformed ZIP central-directory structures.
        Affects 7-Zip 21.07 and p7zip.

        Source: archive_format (zip) + is_corrupted.
        """
        fmt        = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)

        if fmt == "zip" and is_corrupt:
            self._add(
                "R43", "HIGH",
                "CVE-2022-29072: Crafted ZIP may trigger p7zip/7-Zip heap buffer overflow.",
                "Format: ZIP, Corrupted: True",
                cve="CVE-2022-29072",
                rationale=(
                    "CVE-2022-29072 is a heap OOB access in 7-Zip/p7zip when "
                    "parsing malformed ZIP central-directory records, which can "
                    "result in application crash or memory corruption."
                ),
            )

    # ── R44 ───────────────────────────────────────────────────────
    def rule_R44_winrar_format_string(self) -> None:
        """
        CVE-2004-0648: WinRAR 2.90–3.50 format-string vulnerability.

        Format-string specifiers (%s, %d, %x …) embedded in filenames
        of UUE/XXE files inside an archive are passed to printf-family
        functions in WinRAR diagnostic messages, allowing arbitrary
        memory reads/writes.

        Source: filenames (format-string pattern scan).
        """
        hits = [fn for fn in self.filenames if has_format_string(fn)]
        if hits:
            self._add(
                "R44", "HIGH",
                "CVE-2004-0648: Format-string specifiers in filenames — WinRAR format-string vuln.",
                f"Files: {hits[:5]}",
                cve="CVE-2004-0648",
                rationale=(
                    "CVE-2004-0648: WinRAR 2.90–3.50 passes filenames from "
                    "UUE/XXE archive members directly to printf-style functions. "
                    "Format specifiers (%s, %x …) in a filename enable an "
                    "attacker to read or corrupt arbitrary memory."
                ),
            )

    # ── R45 ───────────────────────────────────────────────────────
    def rule_R45_winrar_name_spoof_2023(self) -> None:
        """
        CVE-2023-40477: WinRAR improper validation of user-supplied data.

        A crafted RAR5 archive can cause WinRAR to process data outside
        an allocated buffer during recovery volume processing, potentially
        enabling arbitrary code execution when the user interacts with a
        malicious archive.

        Source: archive_format (rar) + is_corrupted.
        """
        fmt        = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)

        if fmt == "rar" and is_corrupt:
            self._add(
                "R45", "HIGH",
                "CVE-2023-40477: Crafted RAR5 may trigger out-of-bounds write via recovery volume parsing.",
                "Format: RAR, Corrupted: True",
                cve="CVE-2023-40477",
                rationale=(
                    "CVE-2023-40477 (CVSS 7.8): WinRAR improperly validates "
                    "recovery volume data in crafted RAR5 archives, writing "
                    "past an allocated buffer and potentially enabling arbitrary "
                    "code execution with user-level privileges."
                ),
            )

    # ── R46 ───────────────────────────────────────────────────────
    def rule_R46_zip_slip_go_java(self) -> None:
        """
        Zip Slip in non-Ruby ecosystems (representative CVEs):
          CVE-2018-10860: perl libarchive-zip
          CVE-2018-1002209: Java quazip

        Path-traversal entries affect many archive libraries across
        languages.  If traversal entries are present the risk exists
        regardless of which library the target application uses.

        Source: filenames (traversal check, any format except TAR which
        is covered by R34).
        """
        fmt  = self.f.get("archive_format", "").lower()
        if fmt in ("tar", "tgz", "tbz2"):
            return  # Already covered by R34

        hits = [
            fn for fn in self.filenames
            if ".." in fn or fn.startswith("/") or fn.startswith("\\")
        ]
        if hits and fmt not in ("", "unknown"):
            self._add(
                "R46", "HIGH",
                "Zip Slip (CVE-2018-10860/1002209): Path-traversal entries in archive — arbitrary file write.",
                f"Format: {fmt.upper()}, Files: {hits[:5]}",
                cve="CVE-2018-10860",
                rationale=(
                    "Zip Slip affects archive libraries in Python, Java, Go, "
                    "Perl, Ruby and others.  '..' entries in archive names "
                    "escape the extraction directory and overwrite arbitrary "
                    "files, often leading to code execution."
                ),
            )

    # ── R47 ───────────────────────────────────────────────────────
    def rule_R47_xz_utils_backdoor(self) -> None:
        """
        CVE-2024-3094: XZ Utils supply-chain backdoor (CVSS 10.0).

        A malicious actor injected a backdoor into XZ Utils 5.6.0 and
        5.6.1 that, under specific conditions, patches sshd to allow
        unauthorized remote access.  Archives containing .xz files
        bundled with suspicious scripts represent a potential delivery
        vector.

        Detection: .xz files co-present with scripts or executables.

        Source: filenames (extension check for .xz) + script/exe files.
        """
        xz_files  = [fn for fn in self.filenames if fn.lower().endswith(".xz")]
        scripts   = self._files_with_ext(SCRIPT_EXTENSIONS | EXECUTABLE_EXTENSIONS)

        if xz_files and scripts:
            self._add(
                "R47", "HIGH",
                "CVE-2024-3094: .xz archive bundled with scripts — XZ Utils supply-chain pattern.",
                f"XZ files: {xz_files[:3]}, Scripts/Execs: {scripts[:3]}",
                cve="CVE-2024-3094",
                rationale=(
                    "CVE-2024-3094 (CVSS 10.0): XZ Utils 5.6.0–5.6.1 contained "
                    "a sophisticated supply-chain backdoor targeting sshd.  An "
                    "archive bundling .xz files alongside installation scripts "
                    "mirrors the attack pattern used to distribute the backdoor."
                ),
            )

    # ── R50 ───────────────────────────────────────────────────────
    def rule_R50_cab_wusa_bypass(self) -> None:
        """
        CVE-2015-0098: Windows Update Standalone Installer (WUSA) extracts
        CAB files to arbitrary paths, allowing privilege escalation via
        directory junction / hardlink attacks.

        Detection: CAB archive format + presence of system-path directory
        entries or executables.

        Source: archive_format (cab) + filenames.
        """
        fmt = self.f.get("archive_format", "").lower()
        if fmt != "cab":
            return

        sys_dirs = [
            fn for fn in self.filenames
            if any(kw in fn.lower() for kw in SUSPICIOUS_DIRNAMES)
        ]
        has_exe = bool(self._files_with_ext(EXECUTABLE_EXTENSIONS))

        if sys_dirs or has_exe:
            self._add(
                "R50", "HIGH",
                "CVE-2015-0098: CAB archive targeting system paths — WUSA privilege-escalation vector.",
                f"System dirs: {sys_dirs[:3]}, Executables present: {has_exe}",
                cve="CVE-2015-0098",
                rationale=(
                    "CVE-2015-0098: Windows Update Standalone Installer (WUSA) "
                    "extracts CAB archives without proper path validation.  A "
                    "crafted CAB can exploit directory junctions to drop files "
                    "in privileged locations, achieving privilege escalation."
                ),
            )

    # ── R51 ───────────────────────────────────────────────────────
    def rule_R51_office_dde_injection(self) -> None:
        """
        CVE-2017-11826 / DDE injection via Office documents in archive.

        Older Office documents (.doc, .xls) can embed DDE (Dynamic Data
        Exchange) fields that silently execute shell commands when the
        document is opened, even without macros.  This technique was
        heavily used in phishing campaigns (2017–2019).

        Detection: Old Office formats (.doc, .xls, .ppt) present alongside
        phishing keywords in filenames.

        Source: filenames (extension + keyword check).
        """
        old_office = self._files_with_ext({".doc", ".xls", ".ppt", ".rtf"})
        phishing   = [
            fn for fn in old_office
            if any(kw in fn.lower() for kw in PHISHING_KEYWORDS)
        ]

        if phishing:
            self._add(
                "R51", "HIGH",
                "CVE-2017-11826 / DDE: Legacy Office document with phishing name — DDE injection risk.",
                f"Files: {phishing[:5]}",
                cve="CVE-2017-11826",
                rationale=(
                    "Legacy Office formats support DDE fields that execute shell "
                    "commands on document open without any macro interaction. "
                    "CVE-2017-11826 extends this to memory-corruption RCE. "
                    "Phishing filenames are a strong social-engineering signal."
                ),
            )

    # ──────────────────────────────────────────────────────────────
    #  DEDUPLICATION HELPER
    #  Corrupted RAR archives trigger R33/R36/R37/R40/R45 simultaneously.
    #  We keep all of them (different CVEs, different libraries) but
    #  cap their aggregate contribution so a single corrupted RAR does
    #  not dominate the score completely.
    # ──────────────────────────────────────────────────────────────

    def _deduplicate_corruption_rules(self) -> None:
        """
        When multiple corruption-based RAR rules fire simultaneously,
        retain all for CVE reporting but mark the lowest-priority ones
        as LOW severity so they don't each add full weight.

        Priority order (kept at original severity):
            R33 → CVE-2018-20252  (OOB write)
            R37 → CVE-2024-48957  (libarchive OOB read)
            R40 → CVE-2019-18408  (double-free)
            R36 → CVE-2025-53816  (7-zip heap, already MEDIUM)
            R45 → CVE-2023-40477  (RAR5 OOB)
        If ≥ 3 of these fire, demote R40 and R45 to LOW to prevent
        score explosion.
        """
        corruption_ids = {"R33", "R36", "R37", "R40", "R45"}
        fired = [h for h in self.hits if h.rule_id in corruption_ids]
        if len(fired) >= 3:
            demote = {"R40", "R45"}
            for hit in fired:
                if hit.rule_id in demote:
                    hit.severity = "LOW"

    # ──────────────────────────────────────────────────────────────
    #  RUN ALL RULES
    # ──────────────────────────────────────────────────────────────

    def run_all_rules(self) -> list[RuleHit]:
        rules = [
            self.rule_R01_executable_files,
            self.rule_R02_script_files,
            self.rule_R03_shortcut_files,
            self.rule_R04_double_extension,
            self.rule_R05_macro_office_docs,
            self.rule_R06_nested_archives,
            self.rule_R07_encrypted_with_suspicious_files,
            self.rule_R08_decoy_plus_executable,
            self.rule_R09_unicode_rtlo,
            self.rule_R10_space_padding,
            self.rule_R11_decompression_bomb,
            self.rule_R12_excessive_file_count,
            self.rule_R13_path_traversal,
            self.rule_R14_null_byte_filename,
            self.rule_R15_downloader_strings,
            self.rule_R16_execution_strings,
            self.rule_R17_obfuscation_strings,
            self.rule_R18_high_entropy_files,
            self.rule_R19_suspicious_dirs_and_hidden,
            self.rule_R20_phishing_keywords,
            self.rule_R21_winrar_cve_2023_38831,
            self.rule_R22_winrar_buffer_overflow_2018,
            self.rule_R23_infozip_long_comment,
            self.rule_R24_unicode_normalization_spoof,
            self.rule_R25_corrupted_archive,
            self.rule_R26_split_archive,
            self.rule_R27_size_metadata_trick,
            self.rule_R28_timestamp_anomaly,
            self.rule_R29_hardcoded_urls,
            self.rule_R30_mime_extension_mismatch,
            self.rule_R31_oversized_archive,
            self.rule_R32_winrar_ace_path_traversal,
            self.rule_R33_winrar_oob_write,
            self.rule_R34_python_tarfile_traversal,
            self.rule_R35_7zip_symlink_traversal,
            self.rule_R36_7zip_rar5_heap_overflow,
            self.rule_R37_libarchive_rar_oob,
            self.rule_R38_libarchive_windows_rce,
            self.rule_R39_winrar_ntfs_ads,
            self.rule_R40_libarchive_double_free,
            self.rule_R41_infozip_crc_overflow,
            self.rule_R42_commons_compress_oom,
            self.rule_R43_p7zip_heap_overflow,
            self.rule_R44_winrar_format_string,
            self.rule_R45_winrar_name_spoof_2023,
            self.rule_R46_zip_slip_go_java,
            self.rule_R47_xz_utils_backdoor,
            self.rule_R50_cab_wusa_bypass,
            self.rule_R51_office_dde_injection,
        ]

        for rule_fn in rules:
            try:
                rule_fn()
            except Exception as exc:
                print(
                    f"[WARN] {rule_fn.__name__} failed: {exc}",
                    file=sys.stderr,
                )

        self._deduplicate_corruption_rules()
        return self.hits


# ──────────────────────────────────────────────
#  CLASSIFIER
# ──────────────────────────────────────────────

def classify(hits: list[RuleHit]) -> tuple[str, int, str]:
    """
    Returns (classification, severity_score, risk_level).

    Score is capped at 100.
    Classification thresholds:
      MALICIOUS  : any CRITICAL hit  OR  score ≥ 60
      SUSPICIOUS : ≥ 2 HIGH hits     OR  score ≥ 30
      BENIGN     : otherwise
    """
    score      = min(sum(SEVERITY_WEIGHT[h.severity] for h in hits), 100)
    has_crit   = any(h.severity == "CRITICAL" for h in hits)
    high_count = sum(1 for h in hits if h.severity in ("HIGH", "CRITICAL"))

    if has_crit or score >= 60:
        risk = "CRITICAL" if score >= 80 else "HIGH"
        return "MALICIOUS", score, risk
    if high_count >= 2 or score >= 30:
        risk = "HIGH" if score >= 45 else "MEDIUM"
        return "SUSPICIOUS", score, risk
    if score > 0:
        return "SUSPICIOUS", score, "LOW"
    return "BENIGN", 0, "LOW"


# ──────────────────────────────────────────────
#  EXPLANATION GENERATOR
# ──────────────────────────────────────────────

def generate_explanation(
    classification: str,
    hits: list[RuleHit],
    features: dict,
) -> str:
    file_name = features.get("file_name", "unknown")

    if not hits:
        return (
            f"No suspicious indicators were found in '{file_name}'. "
            "The archive appears to contain only standard files with no "
            "anomalous features."
        )

    crit = [h for h in hits if h.severity == "CRITICAL"]
    high = [h for h in hits if h.severity == "HIGH"]
    med  = [h for h in hits if h.severity == "MEDIUM"]
    low  = [h for h in hits if h.severity == "LOW"]

    lines: list[str] = [
        f"The archive '{file_name}' was classified as {classification} "
        f"based on {len(hits)} triggered detection rule(s).\n"
    ]

    for label, group in [
        ("CRITICAL indicators:", crit),
        ("HIGH severity indicators:", high),
        ("MEDIUM severity indicators:", med),
        ("LOW severity indicators:", low),
    ]:
        if group:
            lines.append(label)
            for h in group:
                cve_tag = f" [{h.cve}]" if h.cve else ""
                lines.append(f"  [{h.rule_id}]{cve_tag} {h.description}")
                if h.rationale:
                    lines.append(f"    Why: {h.rationale}")

    cve_hits = sorted({h.cve for h in hits if h.cve})
    if cve_hits:
        lines.append(f"\nReferenced CVEs: {', '.join(cve_hits)}")

    return "\n".join(lines)


# ──────────────────────────────────────────────
#  MAIN ANALYSIS ENTRY POINT
# ──────────────────────────────────────────────

def analyze(raw: dict) -> tuple[DetectionReport, dict]:
    """Analyse a raw Task-1 JSON dict.  Returns (report, features)."""
    features        = normalize_features(raw)
    engine          = ArchiveRuleEngine(features)
    hits            = engine.run_all_rules()
    classification, score, risk_level = classify(hits)
    explanation     = generate_explanation(classification, hits, features)

    report = DetectionReport(
        file_name       = features["file_name"],
        file_path       = features.get("file_path", ""),
        classification  = classification,
        severity_score  = score,
        risk_level      = risk_level,
        triggered_rules = hits,
        explanation     = explanation,
    )
    return report, features


# ──────────────────────────────────────────────
#  OUTPUT FORMATTERS
# ──────────────────────────────────────────────

_SEP  = "=" * 70
_SEP2 = "-" * 70

def print_report(report: DetectionReport, features: dict | None = None) -> None:
    print(f"\n{_SEP}")
    print("  ARCHIVE ANALYSIS REPORT")
    print(_SEP)
    print(f"  File             : {report.file_name}")
    print(f"  Classification   : {report.classification}")
    print(f"  Severity Score   : {report.severity_score}/100")
    print(f"  Risk Level       : {report.risk_level}")
    print(f"  Timestamp        : {report.analysis_timestamp}")

    if features:
        h = features.get("hashes", {})
        if h.get("md5"):
            print(f"  MD5              : {h['md5']}")
        if h.get("sha256"):
            print(f"  SHA256           : {h['sha256']}")

    print(_SEP)

    if report.triggered_rules:
        print(f"\n  Triggered Rules ({len(report.triggered_rules)}):\n")
        for hit in sorted(report.triggered_rules, key=lambda h: h.rule_id):
            cve_tag = f"  ← {hit.cve}" if hit.cve else ""
            print(f"  [{hit.rule_id}] [{hit.severity:<8s}] {hit.description}{cve_tag}")
            print(f"    Evidence  : {hit.evidence}")
            if hit.rationale:
                # Wrap rationale at ~65 chars for readability
                words = hit.rationale.split()
                line, wrapped = [], []
                for w in words:
                    if sum(len(x) + 1 for x in line) + len(w) > 65:
                        wrapped.append(" ".join(line))
                        line = [w]
                    else:
                        line.append(w)
                if line:
                    wrapped.append(" ".join(line))
                prefix = "    Rationale : "
                for i, wl in enumerate(wrapped):
                    print(f"{prefix if i == 0 else ' ' * len(prefix)}{wl}")
            print()
    else:
        print("\n  No rules triggered.\n")

    print(_SEP)
    print("  EXPLANATION")
    print(_SEP)
    print(report.explanation)
    print(f"{_SEP}\n")


def report_to_dict(report: DetectionReport, features: dict | None = None) -> dict:
    result: dict = {
        "file_name":       report.file_name,
        "classification":  report.classification,
        "severity_score":  report.severity_score,
        "risk_level":      report.risk_level,
        "timestamp":       report.analysis_timestamp,
        "triggered_rules": [
            {
                "rule_id":     h.rule_id,
                "severity":    h.severity,
                "description": h.description,
                "evidence":    h.evidence,
                "cve":         h.cve,
                "rationale":   h.rationale,
            }
            for h in report.triggered_rules
        ],
        "explanation": report.explanation,
    }
    if features:
        h = features.get("hashes", {})
        if h:
            result["hashes"] = h
    return result


# ──────────────────────────────────────────────
#  CLI RUNNERS
# ──────────────────────────────────────────────

def _print_summary(summary: dict, total: int) -> None:
    print(f"\n{_SEP}")
    print("  BATCH SUMMARY")
    print(_SEP)
    print(f"  Total analyzed  : {total}")
    print(f"  Benign          : {summary.get('BENIGN', 0)}")
    print(f"  Suspicious      : {summary.get('SUSPICIOUS', 0)}")
    print(f"  Malicious       : {summary.get('MALICIOUS', 0)}")
    print(f"{_SEP}\n")


def _save_combined(summary: dict, results: list, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(
            {"summary": summary, "results": results},
            fh, indent=2, ensure_ascii=False,
        )
    print(f"[+] Combined JSON report saved → {output_path}")


def run_single(json_path: str, output_path: str | None = None) -> dict:
    with open(json_path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    report, features = analyze(raw)
    print_report(report, features)
    result = report_to_dict(report, features)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        print(f"[+] JSON report saved → {output_path}")
    return result


def run_suite(suite_path: str, output_path: str | None = None) -> None:
    with open(suite_path, "r", encoding="utf-8") as fh:
        suite = json.load(fh)

    samples = suite.get("test_samples", [])
    if not samples:
        print("[!] No 'test_samples' key found in suite JSON.")
        return

    print(f"[*] Processing {len(samples)} samples from suite …\n")
    summary: dict[str, int] = {"BENIGN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
    all_results: list[dict] = []

    for i, raw in enumerate(samples, 1):
        clean    = {k: v for k, v in raw.items() if not k.startswith("_")}
        scenario = raw.get("_scenario", f"Sample {i}")
        try:
            report, features = analyze(clean)
            print(f"\n>>> {scenario}")
            print_report(report, features)
            result = report_to_dict(report, features)
            result["scenario"] = scenario
            all_results.append(result)
            summary[result["classification"]] = (
                summary.get(result["classification"], 0) + 1
            )
        except Exception as exc:
            print(f"[ERROR] {scenario}: {exc}", file=sys.stderr)

    _print_summary(summary, len(all_results))
    if output_path:
        _save_combined(summary, all_results, output_path)


def run_batch(directory: str, output_path: str | None = None) -> None:
    json_files = sorted(Path(directory).glob("*.json"))
    if not json_files:
        print(f"[!] No JSON files found in {directory}")
        return

    print(f"[*] Processing {len(json_files)} files …\n")
    summary: dict[str, int] = {"BENIGN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
    all_results: list[dict] = []

    for jf in json_files:
        try:
            with open(jf, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            report, features = analyze(raw)
            print_report(report, features)
            result = report_to_dict(report, features)
            all_results.append(result)
            summary[result["classification"]] = (
                summary.get(result["classification"], 0) + 1
            )
        except Exception as exc:
            print(f"[ERROR] {jf.name}: {exc}", file=sys.stderr)

    _print_summary(summary, len(all_results))
    if output_path:
        _save_combined(summary, all_results, output_path)


# ──────────────────────────────────────────────
#  ARGUMENT PARSER
# ──────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SEC530 Task 2 — Static Rule-Based Archive Detector (v3.0)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "feature_file", nargs="?",
        help="Single Task-1 JSON feature file",
    )
    group.add_argument(
        "--batch", metavar="DIR",
        help="Analyse all JSON files in a directory",
    )
    group.add_argument(
        "--suite", metavar="FILE",
        help="Analyse a test-suite JSON (contains test_samples list)",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Save combined JSON report to file",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.suite:
        run_suite(args.suite, args.output)
    elif args.batch:
        run_batch(args.batch, args.output)
    else:
        run_single(args.feature_file, args.output)


if __name__ == "__main__":
    main()