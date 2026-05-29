"""
SEC530 - Project 3: Smart Compression Archive Analyzer
Task 2: Static Rule-Based Detection Script

Classifies an archive as Benign / Suspicious / Malicious
based on features extracted by Task 1.

Usage:
    python task2_detector.py <feature_json_file>
    python task2_detector.py <feature_json_file> --output report.json
    python task2_detector.py --batch <directory_of_jsons>
"""

import json
import argparse
import sys
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


# ---------------------------------------------
#  DATA STRUCTURES
# ---------------------------------------------

@dataclass
class RuleHit:
    rule_id: str
    severity: str        # LOW / MEDIUM / HIGH / CRITICAL
    description: str
    evidence: str
    cve: Optional[str] = None


@dataclass
class DetectionReport:
    file_name: str
    file_path: str
    classification: str  # BENIGN / SUSPICIOUS / MALICIOUS
    severity_score: int  # 0-100
    risk_level: str      # LOW / MEDIUM / HIGH / CRITICAL
    triggered_rules: list[RuleHit] = field(default_factory=list)
    explanation: str = ""
    analysis_timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )


# ---------------------------------------------
#  SEVERITY WEIGHTS
# ---------------------------------------------

SEVERITY_WEIGHT = {
    "LOW":      5,
    "MEDIUM":  15,
    "HIGH":    30,
    "CRITICAL": 50,
}

# ---------------------------------------------
#  CONSTANTS
# ---------------------------------------------

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".js", ".jse",
    ".vbs", ".vbe", ".scr", ".jar", ".msi", ".com", ".pif",
    ".hta", ".wsf", ".wsh", ".cpl", ".inf", ".reg",
    ".sys", ".drv", ".ocx",
}

SCRIPT_EXTENSIONS = {
    ".ps1", ".bat", ".cmd", ".sh", ".bash", ".py",
    ".vbs", ".js", ".jse", ".vbe", ".wsf", ".wsh",
    ".hta", ".pl", ".rb", ".php",
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
    ".xlam", ".doc", ".xls", ".ppt",
}

SHORTCUT_EXTENSIONS = {".lnk", ".url", ".desktop"}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".xz", ".cab", ".iso", ".tgz", ".tbz2",
}

DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".png", ".jpg"}

DOWNLOADER_KEYWORDS = [
    "invoke-webrequest", "downloadstring", "downloadfile",
    "urldownloadtofile", "bitsadmin", "certutil",
    "wget", "curl", "net.webclient",
    "xmlhttp", "winhttprequest", "adodb.stream",
    "start-bitstransfer",
]

EXECUTION_KEYWORDS = [
    "wscript.shell", "shell.application", "createobject",
    "cmd.exe", "powershell", "mshta", "regsvr32",
    "rundll32", "cscript", "wscript", "exec",
    "shellexecute", "winexec", "createprocess",
]

OBFUSCATION_KEYWORDS = [
    "base64", "frombase64string", "convert]::frombase64",
    "char(", "chr(", "charcode", "-enc ", "-encodedcommand",
    "iex(", "invoke-expression", "\\x",
]

PHISHING_KEYWORDS = [
    "invoice", "payment", "urgent", "bank", "account",
    "verify", "suspended", "click here", "confirm",
    "password", "credential", "login", "update required",
]

SUSPICIOUS_DIRNAMES = [
    "temp", "tmp", "appdata", "roaming", "startup",
    "system32", "syswow64", "windows",
]


# ---------------------------------------------
#  HELPER UTILITIES
# ---------------------------------------------

def get_extension(filename: str) -> str:
    return Path(filename).suffix.lower()


def get_all_extensions(filename: str) -> list[str]:
    return [s.lower() for s in Path(filename).suffixes]


def has_rtlo(filename: str) -> bool:
    return "\u202e" in filename


def is_hidden_by_spaces(filename: str) -> bool:
    return "     " in Path(filename).stem


def contains_keyword(text: str, keywords: list[str]) -> list[str]:
    lower = text.lower()
    return [kw for kw in keywords if kw in lower]


# ---------------------------------------------
#  TASK 1 JSON NORMALIZER
#
#  Task 1 output structure:
#    "1_basic_info"          -> file_name, file_size, mime_type, hashes
#    "2_archive_metadata"    -> format, compression_ratio, password_protected,
#                               is_split_archive, corrupted, file_count, comment
#    "3_internal_files"      -> list of per-file dicts
#    "4_security_indicators" -> pre-computed boolean flags
#    "5_content_indicators"  -> urls_found, suspicious_commands
#
#  Field usage map:
#    file_name            -> report header, explanation
#    file_size            -> R31 (oversized archive)
#    mime_type            -> R30 (archive-level MIME check)
#    hashes               -> displayed in report output
#    archive_format       -> R21 (WinRAR CVE), R22, R23
#    compression_ratio    -> R11 (zip bomb)
#    is_encrypted         -> R07 (encrypted + exe)
#    is_split             -> R26 (split archive)
#    is_corrupted         -> R22, R25
#    file_count           -> R12 (excessive count, from metadata)
#    archive_comment      -> R23 (long comment / CVE-2016-9844)
#    total_uncompressed   -> R11 (zip bomb size check)
#    max_nested_depth     -> R06 (nested archive depth)
#    t1_has_executables   -> R01 shortcut
#    t1_has_office_macros -> R05 shortcut
#    t1_has_lnk           -> R03 shortcut
#    t1_has_nested_archives -> R06 shortcut
#    t1_double_extensions -> R04 shortcut (merge with own findings)
#    t1_suspicious_filenames -> R19 (may include EXCESSIVE_FILE_COUNT flag)
#    t1_unicode_rtlo      -> R09 shortcut
#    t1_extension_mismatches -> R30 shortcut
#    t1_archive_bomb      -> R11 shortcut
#    t1_decoy_and_exe     -> R08 shortcut
#    files[]              -> R01-R10, R13-R14, R18-R20, R27-R28, R30 (per-file)
#      .name              -> extension, double-ext, RTLO, space padding,
#                            path traversal, null byte, phishing keyword,
#                            suspicious dirname, MIME mismatch checks
#      .compressed_size   -> R27 (zero-byte metadata trick)
#      .uncompressed_size -> R27 (zero-byte metadata trick)
#      .timestamp         -> R28 (anomalous timestamp)
#      .entropy           -> R18 (high entropy = packed/encrypted payload)
#      .is_directory      -> R19 (directory name check)
#      .detected_mime     -> R30 (MIME vs extension mismatch)
#      .is_hidden         -> R19 (hidden file check)
#    extracted_strings[]  -> R15 (downloader), R16 (execution),
#                            R17 (obfuscation), R29 (URL/IP)
#      (urls_found + suspicious_commands merged)
# ---------------------------------------------

def normalize_features(raw: dict) -> dict:
    basic   = raw.get("1_basic_info", {})
    meta    = raw.get("2_archive_metadata", {})
    files   = raw.get("3_internal_files", [])
    sec     = raw.get("4_security_indicators", {})
    content = raw.get("5_content_indicators", {})

    normalized_files = []
    for fi in files:
        normalized_files.append({
            "name":              fi.get("internal_path") or fi.get("file_name", ""),
            "compressed_size":   fi.get("compressed_size", 0),
            "uncompressed_size": fi.get("uncompressed_size", 0),
            "timestamp":         fi.get("timestamp", ""),
            "entropy":           fi.get("entropy", 0),
            "is_directory":      fi.get("is_directory", False),
            "detected_mime":     fi.get("detected_mime", ""),
            "is_hidden":         fi.get("is_hidden", False),
            "has_double_extension":    fi.get("has_double_extension", False),
            "is_executable_or_script": fi.get("is_executable_or_script", False),
        })

    extracted_strings = (
        content.get("urls_found", []) +
        content.get("suspicious_commands", [])
    )

    total_uncompressed = sum(fi.get("uncompressed_size", 0) for fi in files)

    return {
        # identity
        "file_name":     basic.get("file_name", "unknown"),
        "file_size":     basic.get("file_size", 0),
        "mime_type":     basic.get("mime_type", ""),
        "hashes":        basic.get("hashes", {}),

        # archive metadata
        "archive_format":          meta.get("format", "unknown"),
        "compression_ratio":       meta.get("compression_ratio", 0),
        "is_encrypted":            meta.get("password_protected", False),
        "is_split":                meta.get("is_split_archive", False),
        "is_corrupted":            meta.get("corrupted", False),
        "file_count":              meta.get("file_count", len(files)),
        "archive_comment":         meta.get("comment") or "",
        "total_uncompressed_size": total_uncompressed,

        # Task 1 pre-computed flags
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

        # file list + strings
        "files":             normalized_files,
        "extracted_strings": extracted_strings,
    }


# ---------------------------------------------
#  RULE ENGINE
# ---------------------------------------------

class ArchiveRuleEngine:

    def __init__(self, features: dict):
        self.f = features
        self.hits: list[RuleHit] = []
        self.files: list[dict] = features.get("files", [])
        self.strings: list[str] = features.get("extracted_strings", [])
        self.filenames: list[str] = [fi.get("name", "") for fi in self.files]

    def _add(self, rule_id, severity, description, evidence, cve=None):
        self.hits.append(RuleHit(rule_id, severity, description, evidence, cve))

    def _files_with_ext(self, ext_set: set) -> list[str]:
        return [fn for fn in self.filenames if get_extension(fn) in ext_set]

    def _strings_combined(self) -> str:
        return " ".join(self.strings).lower()

    # ---------------------------------------------
    #  RULES
    # ---------------------------------------------

    def rule_R01_executable_files(self):
        """R01 - Executable or binary files present.
        Source: filenames (extension check) + t1_has_executables flag"""
        found = self._files_with_ext(EXECUTABLE_EXTENSIONS)
        if found or self.f.get("t1_has_executables"):
            evidence = found[:5] if found else ["(flagged by Task 1 extractor)"]
            self._add("R01", "HIGH",
                      "Archive contains executable or binary files.",
                      f"Files: {evidence}",
                      cve="CVE-2019-0541")

    def rule_R02_script_files(self):
        """R02 - Script files present.
        Source: filenames (extension check)"""
        found = self._files_with_ext(SCRIPT_EXTENSIONS)
        if found:
            self._add("R02", "MEDIUM",
                      "Archive contains script files that can execute commands.",
                      f"Files: {found[:5]}",
                      cve="CVE-2016-7201")

    def rule_R03_shortcut_files(self):
        """R03 - Shortcut files (.lnk / .url) present.
        Source: filenames (extension check) + t1_has_lnk flag"""
        found = self._files_with_ext(SHORTCUT_EXTENSIONS)
        if found or self.f.get("t1_has_lnk"):
            evidence = found[:5] if found else ["(flagged by Task 1 extractor)"]
            self._add("R03", "HIGH",
                      "Shortcut files (.lnk/.url) are used to execute hidden payloads.",
                      f"Files: {evidence}",
                      cve="CVE-2010-2568")

    def rule_R04_double_extension(self):
        """R04 - Double-extension filenames (e.g. invoice.pdf.exe).
        Source: filenames (all suffixes) + t1_double_extensions list"""
        own = []
        for fn in self.filenames:
            exts = get_all_extensions(fn)
            if len(exts) >= 2:
                if exts[-1] in EXECUTABLE_EXTENSIONS and exts[-2] in DECOY_EXTENSIONS:
                    own.append(fn)
        all_hits = list(set(own + self.f.get("t1_double_extensions", [])))
        if all_hits:
            self._add("R04", "CRITICAL",
                      "Double-extension filenames disguise executables as documents.",
                      f"Files: {all_hits[:5]}",
                      cve="CVE-2001-0927")

    def rule_R05_macro_office_docs(self):
        """R05 - Macro-enabled Office documents present.
        Source: filenames (extension check) + t1_has_office_macros flag"""
        found = self._files_with_ext(MACRO_EXTENSIONS)
        if found or self.f.get("t1_has_office_macros"):
            evidence = found[:5] if found else ["(flagged by Task 1 extractor)"]
            self._add("R05", "HIGH",
                      "Macro-enabled Office documents can execute arbitrary code on open.",
                      f"Files: {evidence}",
                      cve="CVE-2017-11882")

    def rule_R06_nested_archives(self):
        """R06 - Nested archives (AV evasion technique).
        Source: filenames (extension check) + t1_has_nested_archives + max_nested_depth"""
        found = self._files_with_ext(ARCHIVE_EXTENSIONS)
        depth = self.f.get("max_nested_depth", 0)
        if found or self.f.get("t1_has_nested_archives"):
            severity = "CRITICAL" if depth >= 3 else "HIGH"
            evidence = found[:5] if found else ["(flagged by Task 1 extractor)"]
            self._add("R06", severity,
                      "Nested archives are used to evade AV scanning and detection.",
                      f"Archives: {evidence}, max depth: {depth}",
                      cve="CVE-2012-1459")

    def rule_R07_encrypted_with_suspicious_files(self):
        """R07 - Encrypted archive containing suspicious content.
        Source: is_encrypted + filenames (extension check)"""
        is_enc = self.f.get("is_encrypted", False)
        suspicious = self._files_with_ext(EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS)
        if is_enc and suspicious:
            self._add("R07", "CRITICAL",
                      "Encrypted archive with executables/scripts hides payloads from AV.",
                      f"Encrypted: True, Suspicious files: {suspicious[:3]}",
                      cve="CVE-2020-17087")
        elif is_enc:
            self._add("R07", "LOW",
                      "Archive is encrypted — contents cannot be scanned.",
                      "Encrypted: True")

    def rule_R08_decoy_plus_executable(self):
        """R08 - Decoy document + executable (classic dropper pattern).
        Source: filenames (extension check) + t1_decoy_and_exe flag"""
        decoys = self._files_with_ext(DECOY_EXTENSIONS)
        execs  = self._files_with_ext(EXECUTABLE_EXTENSIONS)
        if (decoys and execs) or self.f.get("t1_decoy_and_exe"):
            self._add("R08", "CRITICAL",
                      "Archive contains both a decoy document and an executable — classic dropper pattern.",
                      f"Decoys: {decoys[:3]}, Executables: {execs[:3]}",
                      cve="CVE-2018-0802")

    def rule_R09_unicode_rtlo(self):
        """R09 - Right-to-Left Override (RTLO) character in filename (U+202E).
        Source: filenames (character check) + t1_unicode_rtlo flag"""
        hits = [fn for fn in self.filenames if has_rtlo(fn)]
        if hits or self.f.get("t1_unicode_rtlo"):
            evidence = hits[:5] if hits else ["(flagged by Task 1 extractor)"]
            self._add("R09", "CRITICAL",
                      "RTLO character (U+202E) reverses the filename to hide the real extension.",
                      f"Files: {evidence}",
                      cve="CVE-2009-3376")

    def rule_R10_space_padding(self):
        """R10 - Filename padded with spaces to hide extension.
        Source: filenames (stem whitespace check)"""
        hits = [fn for fn in self.filenames if is_hidden_by_spaces(fn)]
        if hits:
            self._add("R10", "HIGH",
                      "Filename padded with spaces to hide the true extension in file managers.",
                      f"Files: {hits[:5]}",
                      cve="CVE-2001-0680")

    def rule_R11_decompression_bomb(self):
        """R11 - Zip bomb / decompression bomb.
        Source: compression_ratio + total_uncompressed_size + t1_archive_bomb flag"""
        ratio = self.f.get("compression_ratio", 0)
        total = self.f.get("total_uncompressed_size", 0)
        GB    = 1_073_741_824
        if self.f.get("t1_archive_bomb") or (ratio > 100 and total > GB):
            self._add("R11", "CRITICAL",
                      "Extreme compression ratio indicates a potential decompression bomb.",
                      f"Ratio: {ratio:.1f}x, Uncompressed: {total / GB:.2f} GB",
                      cve="CVE-2019-10769")
        elif ratio > 50:
            self._add("R11", "HIGH",
                      "Very high compression ratio — possible zip bomb or heavily compressed payload.",
                      f"Ratio: {ratio:.1f}x",
                      cve="CVE-2019-10769")

    def rule_R12_excessive_file_count(self):
        """R12 - Unusually high number of files (zip bomb variant).
        Source: file_count (from metadata)"""
        count = self.f.get("file_count", len(self.files))
        if count > 10000:
            self._add("R12", "HIGH",
                      "Extremely high file count — may cause resource exhaustion.",
                      f"File count: {count}",
                      cve="CVE-2021-35517")
        elif count > 1000:
            self._add("R12", "MEDIUM",
                      "High file count — unusual for standard archives.",
                      f"File count: {count}")

    def rule_R13_path_traversal(self):
        """R13 - Path traversal filenames (Zip Slip).
        Source: filenames (.. and leading / check)"""
        hits = [fn for fn in self.filenames if ".." in fn or fn.startswith("/")]
        if hits:
            self._add("R13", "CRITICAL",
                      "Path traversal filenames can overwrite system files on extraction.",
                      f"Files: {hits[:5]}",
                      cve="CVE-2018-3718")

    def rule_R14_null_byte_filename(self):
        """R14 - Null byte in filename (parser confusion attack).
        Source: filenames (null byte check)"""
        hits = [fn for fn in self.filenames if "\x00" in fn]
        if hits:
            self._add("R14", "CRITICAL",
                      "Null byte in filename can bypass extension checks in vulnerable parsers.",
                      f"Files: {hits[:3]}",
                      cve="CVE-2008-5518")

    def rule_R15_downloader_strings(self):
        """R15 - Download commands found in extracted strings.
        Source: extracted_strings (urls_found + suspicious_commands)"""
        found = contains_keyword(self._strings_combined(), DOWNLOADER_KEYWORDS)
        if found:
            self._add("R15", "CRITICAL",
                      "Extracted strings contain download commands indicating staged malware delivery.",
                      f"Keywords: {found}",
                      cve="CVE-2017-0199")

    def rule_R16_execution_strings(self):
        """R16 - Shell execution patterns found in extracted strings.
        Source: extracted_strings (urls_found + suspicious_commands)"""
        found = contains_keyword(self._strings_combined(), EXECUTION_KEYWORDS)
        if found:
            self._add("R16", "HIGH",
                      "Extracted strings reference shell execution APIs — possible malicious script.",
                      f"Keywords: {found}",
                      cve="CVE-2014-6332")

    def rule_R17_obfuscation_strings(self):
        """R17 - Obfuscation techniques found in extracted strings.
        Source: extracted_strings (urls_found + suspicious_commands)"""
        found = contains_keyword(self._strings_combined(), OBFUSCATION_KEYWORDS)
        if found:
            self._add("R17", "HIGH",
                      "Obfuscation techniques detected — attacker is hiding payload from static analysis.",
                      f"Keywords: {found}",
                      cve="CVE-2020-0601")

    def rule_R18_high_entropy_files(self):
        """R18 - High-entropy files (packed or encrypted payload).
        Source: files[].entropy"""
        safe_exts = {".zip", ".gz", ".jpg", ".png"}
        hits = [
            fi["name"] for fi in self.files
            if fi.get("entropy", 0) >= 7.5
            and get_extension(fi.get("name", "")) not in safe_exts
        ]
        if hits:
            self._add("R18", "HIGH",
                      "High-entropy files suggest encrypted or packed payloads embedded in the archive.",
                      f"Files: {hits[:5]}",
                      cve="CVE-2022-30190")

    def rule_R19_suspicious_dirs_and_hidden(self):
        """R19 - Suspicious directory names and hidden files.
        Source: files[].is_directory + files[].name + files[].is_hidden
                + t1_suspicious_filenames"""
        dirs = [fi.get("name", "") for fi in self.files if fi.get("is_directory")]
        dir_hits = [d for d in dirs if any(kw in d.lower() for kw in SUSPICIOUS_DIRNAMES)]

        hidden_hits = [fi.get("name", "") for fi in self.files if fi.get("is_hidden")]

        t1_extra = [
            s for s in self.f.get("t1_suspicious_filenames", [])
            if s not in dir_hits and s not in hidden_hits
        ]

        all_hits = dir_hits + hidden_hits + t1_extra
        if all_hits:
            self._add("R19", "MEDIUM",
                      "Suspicious directory names, hidden files, or Task 1 flagged filenames detected.",
                      f"Directories: {dir_hits[:3]}, Hidden: {hidden_hits[:3]}, Other: {t1_extra[:3]}",
                      cve="CVE-2017-8570")

    def rule_R20_phishing_keywords(self):
        """R20 - Phishing-related keywords in filenames.
        Source: filenames"""
        hits = [fn for fn in self.filenames
                if any(kw in fn.lower() for kw in PHISHING_KEYWORDS)]
        if hits:
            self._add("R20", "MEDIUM",
                      "Phishing-related terms found in filenames — indicates social engineering attack.",
                      f"Files: {hits[:5]}",
                      cve="CVE-2017-0262")

    def rule_R21_winrar_rce(self):
        """R21 - CVE-2023-38831: WinRAR path traversal RCE.
        Source: archive_format + filenames (.. check) + filenames (exe check)"""
        fmt = self.f.get("archive_format", "").lower()
        has_traversal = any(".." in fn for fn in self.filenames)
        has_exe = bool(self._files_with_ext({".exe", ".dll", ".bat"}))
        if fmt == "rar" and has_traversal and has_exe:
            self._add("R21", "CRITICAL",
                      "Structure resembles CVE-2023-38831 WinRAR RCE — path traversal + executable in RAR.",
                      "Format: RAR, Path traversal detected, Executables present.",
                      cve="CVE-2023-38831")

    def rule_R22_winrar_buffer_overflow(self):
        """R22 - CVE-2018-18384: WinRAR buffer overflow.
        Source: archive_format + is_corrupted + filenames (long path check)"""
        fmt = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        has_long_path = any(len(fn) > 255 for fn in self.filenames)
        if fmt in ("rar", "zip") and (is_corrupt or has_long_path):
            self._add("R22", "HIGH",
                      "Malformed structure or oversized path may trigger CVE-2018-18384 WinRAR buffer overflow.",
                      f"Format: {fmt.upper()}, Corrupted: {is_corrupt}, Long path: {has_long_path}",
                      cve="CVE-2018-18384")

    def rule_R23_infozip_long_comment(self):
        """R23 - CVE-2016-9844: Info-ZIP buffer overflow via long comment.
        Source: archive_format + archive_comment (length check)"""
        fmt = self.f.get("archive_format", "").lower()
        comment_len = len(self.f.get("archive_comment", ""))
        if fmt == "zip" and comment_len > 512:
            self._add("R23", "HIGH",
                      "Excessively long archive comment may trigger Info-ZIP buffer overflow (CVE-2016-9844).",
                      f"Comment length: {comment_len} bytes",
                      cve="CVE-2016-9844")

    def rule_R24_unicode_normalization_spoof(self):
        """R24 - CVE-2025-8088: Unicode normalization filename spoofing.
        Source: filenames (non-ASCII char + executable extension check)"""
        hits = [
            fn for fn in self.filenames
            if any(ord(c) > 127 for c in fn)
            and get_extension(fn) in EXECUTABLE_EXTENSIONS
        ]
        if hits:
            self._add("R24", "CRITICAL",
                      "Unicode normalization spoofing — filename appears benign but has executable extension.",
                      f"Files: {hits[:5]}",
                      cve="CVE-2025-8088")

    def rule_R25_corrupted_archive(self):
        """R25 - Corrupted or malformed archive (evasion or exploit delivery).
        Source: is_corrupted"""
        if self.f.get("is_corrupted"):
            self._add("R25", "MEDIUM",
                      "Archive is corrupted or malformed — may evade automated scanners or exploit parsers.",
                      "is_corrupted: True",
                      cve="CVE-2016-1541")

    def rule_R26_split_archive(self):
        """R26 - Split archive (parts may reassemble into different payload).
        Source: is_split"""
        if self.f.get("is_split"):
            self._add("R26", "MEDIUM",
                      "Split archive detected — the final reassembled payload may differ from individual parts.",
                      "is_split: True",
                      cve="CVE-2005-2349")

    def rule_R27_size_metadata_trick(self):
        """R27 - Zero uncompressed size but non-zero compressed size (header manipulation).
        Source: files[].uncompressed_size + files[].compressed_size"""
        hits = [
            fi.get("name", "unknown") for fi in self.files
            if fi.get("uncompressed_size", 1) == 0 and fi.get("compressed_size", 0) > 0
        ]
        if hits:
            self._add("R27", "HIGH",
                      "Files with non-zero compressed size but zero uncompressed size — header manipulation.",
                      f"Files: {hits[:5]}",
                      cve="CVE-2014-9390")

    def rule_R28_timestamp_anomaly(self):
        """R28 - Impossible or anomalous file timestamps (anti-forensics).
        Source: files[].timestamp"""
        hits = []
        for fi in self.files:
            ts = fi.get("timestamp", "")
            if ts:
                m = re.search(r"(\d{4})", ts)
                if m:
                    year = int(m.group(1))
                    if year < 1980 or year > 2030:
                        hits.append((fi.get("name", "?"), ts))
        if hits:
            self._add("R28", "LOW",
                      "Anomalous file timestamps — may indicate anti-forensics tampering.",
                      f"Files: {hits[:3]}",
                      cve="CVE-2008-0888")

    def rule_R29_hardcoded_urls(self):
        """R29 - Hardcoded URLs or IP addresses in extracted strings.
        Source: extracted_strings (urls_found + suspicious_commands)"""
        url_pat = re.compile(r"(https?://[^\s\"'<>]+|(\d{1,3}\.){3}\d{1,3}(:\d+)?)")
        found_urls = []
        for s in self.strings:
            found_urls.extend(m[0] for m in url_pat.findall(s) if m[0])
        if found_urls:
            sev = "HIGH" if len(found_urls) > 3 else "MEDIUM"
            self._add("R29", sev,
                      "Hardcoded URL or IP address — may indicate C2 communication or staged download.",
                      f"URLs: {found_urls[:5]}",
                      cve="CVE-2021-40444")

    def rule_R30_mime_extension_mismatch(self):
        """R30 - File extension does not match detected MIME type.
        Source: files[].detected_mime + files[].name (extension)
                + t1_extension_mismatches list
                + mime_type (archive-level check)"""
        own = []
        for fi in self.files:
            ext  = get_extension(fi.get("name", ""))
            mime = fi.get("detected_mime", "")
            if ext and mime:
                if ext == ".pdf" and "pdf" not in mime:
                    own.append(fi.get("name"))
                elif ext in {".jpg", ".jpeg"} and "jpeg" not in mime and "image" not in mime:
                    own.append(fi.get("name"))
        all_hits = list(set(own + self.f.get("t1_extension_mismatches", [])))
        if all_hits:
            self._add("R30", "HIGH",
                      "File extension does not match detected MIME type — possible disguised executable.",
                      f"Files: {all_hits[:5]}",
                      cve="CVE-2012-0010")

    def rule_R31_oversized_archive(self):
        """R31 - Oversized archive file (evasion or DoS).
        Source: file_size"""
        size = self.f.get("file_size", 0)
        GB = 1_073_741_824
        if size > 2 * GB:
            self._add("R31", "MEDIUM",
                      "Archive size exceeds 2 GB — may be used to overwhelm analysis tools or hide content.",
                      f"Size: {size / GB:.2f} GB",
                      cve="CVE-2019-3462")


    def rule_R32_winrar_ace_path_traversal(self):
        """R32 - CVE-2018-20250: WinRAR ACE format absolute path traversal RCE.
        The UNACEV2.DLL library ignores the extraction destination and uses
        the filename field as an absolute path, enabling startup folder persistence.
        Source: archive_format + filenames (ACE/absolute path indicators)"""
        fmt = self.f.get("archive_format", "").lower()
        has_abs = any(
            fn.startswith("C:\\") or fn.startswith("/") or "Startup" in fn
            for fn in self.filenames
        )
        has_exe = bool(self._files_with_ext({".exe", ".dll", ".bat", ".ps1"}))
        if has_abs and has_exe:
            self._add("R32", "CRITICAL",
                      "Absolute path in archive filename — may exploit CVE-2018-20250 WinRAR ACE path traversal RCE.",
                      f"Format: {fmt.upper()}, Absolute paths + executables detected.",
                      cve="CVE-2018-20250")

    def rule_R33_winrar_ace_oob_write(self):
        """R33 - CVE-2018-20252 / CVE-2018-20253: WinRAR out-of-bounds write
        during parsing of crafted ACE/RAR archives leading to arbitrary code execution.
        Source: is_corrupted + archive_format"""
        fmt = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        if fmt in ("rar", "zip") and is_corrupt:
            self._add("R33", "HIGH",
                      "Crafted/corrupted RAR or ZIP may trigger out-of-bounds write (CVE-2018-20252/20253).",
                      f"Format: {fmt.upper()}, Corrupted: True",
                      cve="CVE-2018-20252")

    def rule_R34_python_tarfile_traversal(self):
        """R34 - CVE-2007-4559: Python tarfile module path traversal.
        The extract/extractall functions do not sanitize member paths,
        allowing overwrite of arbitrary files on the system.
        Source: archive_format + filenames (.. check)"""
        fmt = self.f.get("archive_format", "").lower()
        hits = [fn for fn in self.filenames if ".." in fn or fn.startswith("/")]
        if fmt == "tar" and hits:
            self._add("R34", "HIGH",
                      "TAR archive with path traversal entries — may exploit CVE-2007-4559 Python tarfile traversal.",
                      f"Files: {hits[:5]}",
                      cve="CVE-2007-4559")

    def rule_R35_7zip_symlink_traversal(self):
        """R35 - CVE-2025-11001 / CVE-2025-11002: 7-Zip symbolic link path traversal RCE.
        Maliciously crafted ZIP files with symlinks escape the extraction directory
        and allow arbitrary file writes leading to code execution.
        Source: archive_format + filenames (symlink-like names)"""
        fmt = self.f.get("archive_format", "").lower()
        # Symlink entries often have very short names pointing to absolute paths
        has_traversal = any(".." in fn or fn.startswith("/") for fn in self.filenames)
        if fmt == "zip" and has_traversal:
            self._add("R35", "CRITICAL",
                      "ZIP with traversal/symlink entries — may exploit CVE-2025-11001/11002 7-Zip RCE.",
                      f"Traversal paths detected in ZIP archive.",
                      cve="CVE-2025-11001")

    def rule_R36_7zip_rar5_heap_overflow(self):
        """R36 - CVE-2025-53816: 7-Zip heap-based buffer overflow in RAR5 decoder.
        A maliciously crafted RAR5 archive can cause memory corruption (DoS/potential RCE).
        Source: archive_format + is_corrupted"""
        fmt = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        if fmt == "rar" and is_corrupt:
            self._add("R36", "HIGH",
                      "Corrupted RAR5 archive may trigger CVE-2025-53816 7-Zip heap buffer overflow.",
                      "Format: RAR, Corrupted: True",
                      cve="CVE-2025-53816")

    def rule_R37_libarchive_rar_oob(self):
        """R37 - CVE-2024-48957: libarchive out-of-bounds access via crafted RAR file.
        The execute_filter_audio function in RAR support allows memory corruption
        via a specially crafted archive.
        Source: archive_format + is_corrupted"""
        fmt = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        if fmt == "rar" and is_corrupt:
            self._add("R37", "HIGH",
                      "Crafted RAR may trigger CVE-2024-48957 libarchive out-of-bounds read.",
                      "Format: RAR, Corrupted: True",
                      cve="CVE-2024-48957")

    def rule_R38_libarchive_windows_rce(self):
        """R38 - CVE-2024-20696: libarchive RCE on Windows via malformed archive.
        Affects Windows 10+ (libarchive integrated in Explorer). Opening a crafted
        ZIP/TAR/CAB can execute arbitrary code under the user context.
        Source: archive_format + filenames (long/malformed names)"""
        fmt = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        has_long = any(len(fn) > 200 for fn in self.filenames)
        if fmt in ("zip", "tar", "cab") and (is_corrupt or has_long):
            self._add("R38", "CRITICAL",
                      "Malformed archive may trigger CVE-2024-20696 libarchive Windows RCE.",
                      f"Format: {fmt.upper()}, Corrupted: {is_corrupt}, Long filenames: {has_long}",
                      cve="CVE-2024-20696")

    def rule_R39_winrar_ntfs_ads(self):
        """R39 - CVE-2025-6218: WinRAR path traversal via NTFS Alternate Data Streams.
        Allows writing files outside the extraction directory using ADS notation.
        Source: filenames (colon ADS notation or traversal sequences)"""
        hits = [fn for fn in self.filenames if ":" in fn and not fn.startswith("C:")]
        traversal = [fn for fn in self.filenames if ".." in fn]
        if hits or traversal:
            all_hits = list(set(hits + traversal))
            self._add("R39", "CRITICAL",
                      "NTFS Alternate Data Streams or traversal in filenames — may exploit CVE-2025-6218 WinRAR path traversal.",
                      f"Files: {all_hits[:5]}",
                      cve="CVE-2025-6218")

    def rule_R40_libarchive_double_free(self):
        """R40 - CVE-2019-18408 / CVE-2025-5914: libarchive double-free in RAR decoder.
        A crafted RAR archive triggers a double-free condition in parse_codes()
        leading to memory corruption or DoS.
        Source: archive_format + is_corrupted"""
        fmt = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        if fmt == "rar" and is_corrupt:
            self._add("R40", "HIGH",
                      "Crafted RAR may trigger CVE-2019-18408/CVE-2025-5914 libarchive double-free.",
                      "Format: RAR, Corrupted: True",
                      cve="CVE-2019-18408")

    def rule_R41_zip_slip_generic(self):
        """R41 - CVE-2018-1000544 / CVE-2018-1002208: Zip Slip in multiple libraries.
        Path traversal via archive extraction affects Ruby rubyzip, .NET SharpZipLib
        and dozens of other libraries — any archive with .. in filenames is a risk.
        Source: filenames (.. check, not already covered by R13 for non-ZIP formats)"""
        fmt = self.f.get("archive_format", "").lower()
        if fmt in ("zip", "7z", "rar", "tar"):
            hits = [fn for fn in self.filenames if ".." in fn]
            if hits:
                self._add("R41", "HIGH",
                          "Zip Slip pattern — path traversal entries affect multiple extraction libraries (CVE-2018-1000544).",
                          f"Files: {hits[:5]}",
                          cve="CVE-2018-1000544")

    def rule_R42_infozip_envvar_injection(self):
        """R42 - CVE-2014-8139 / CVE-2014-8140: Info-ZIP unzip CRC/header buffer overflow.
        Crafted ZIP files with malformed CRC or extra fields trigger buffer overflows
        in unzip versions before 6.0 patch level 11.
        Source: archive_format + is_corrupted"""
        fmt = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        comment_len = len(self.f.get("archive_comment", ""))
        if fmt == "zip" and (is_corrupt or comment_len > 256):
            self._add("R42", "HIGH",
                      "Malformed ZIP may trigger Info-ZIP CRC/header buffer overflow (CVE-2014-8139/8140).",
                      f"Corrupted: {is_corrupt}, Comment length: {comment_len}",
                      cve="CVE-2014-8139")

    def rule_R43_zip_excessive_compression(self):
        """R43 - CVE-2021-36090 / CVE-2021-35516: Apache Commons Compress zip bomb / OOM.
        Excessively nested or highly compressed ZIP entries cause OutOfMemoryError,
        enabling denial of service against Java applications using Commons Compress.
        Source: compression_ratio + file_count"""
        ratio = self.f.get("compression_ratio", 0)
        count = self.f.get("file_count", 0)
        fmt   = self.f.get("archive_format", "").lower()
        if fmt == "zip" and (ratio > 30 or count > 500):
            self._add("R43", "MEDIUM",
                      "High compression or file count may trigger Apache Commons Compress OOM (CVE-2021-36090/35516).",
                      f"Ratio: {ratio:.1f}x, File count: {count}",
                      cve="CVE-2021-36090")

    def rule_R44_p7zip_heap_overflow(self):
        """R44 - CVE-2022-29072 / p7zip heap overflow: Heap buffer overflow in p7zip
        via crafted ZIP archive. The NArchive::NZip::CInArchive::FindCd function
        allows out-of-bounds memory access.
        Source: archive_format + is_corrupted"""
        fmt = self.f.get("archive_format", "").lower()
        is_corrupt = self.f.get("is_corrupted", False)
        if fmt == "zip" and is_corrupt:
            self._add("R44", "HIGH",
                      "Crafted ZIP may trigger p7zip heap buffer overflow (CVE-2022-29072).",
                      "Format: ZIP, Corrupted: True",
                      cve="CVE-2022-29072")

    def rule_R45_winrar_format_string(self):
        """R45 - CVE-2004-0648: WinRAR 2.90-3.50 format string vulnerability.
        Format string specifiers in UUE/XXE filenames within archives allow
        arbitrary code execution when WinRAR displays diagnostic messages.
        Source: filenames (format string patterns)"""
        import re as _re
        fmt_pattern = _re.compile(r'%[0-9]*[sdfxp]')
        hits = [fn for fn in self.filenames if fmt_pattern.search(fn)]
        if hits:
            self._add("R45", "HIGH",
                      "Format string patterns in filenames — may exploit CVE-2004-0648 WinRAR format string vulnerability.",
                      f"Files: {hits[:5]}",
                      cve="CVE-2004-0648")

    # ---------------------------------------------
    #  RUN ALL RULES
    # ---------------------------------------------

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
            self.rule_R21_winrar_rce,
            self.rule_R22_winrar_buffer_overflow,
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
            self.rule_R33_winrar_ace_oob_write,
            self.rule_R34_python_tarfile_traversal,
            self.rule_R35_7zip_symlink_traversal,
            self.rule_R36_7zip_rar5_heap_overflow,
            self.rule_R37_libarchive_rar_oob,
            self.rule_R38_libarchive_windows_rce,
            self.rule_R39_winrar_ntfs_ads,
            self.rule_R40_libarchive_double_free,
            self.rule_R41_zip_slip_generic,
            self.rule_R42_infozip_envvar_injection,
            self.rule_R43_zip_excessive_compression,
            self.rule_R44_p7zip_heap_overflow,
            self.rule_R45_winrar_format_string,
        ]
        for rule in rules:
            try:
                rule()
            except Exception as e:
                print(f"[WARN] {rule.__name__} failed: {e}", file=sys.stderr)
        return self.hits


# ---------------------------------------------
#  CLASSIFIER
# ---------------------------------------------

def classify(hits: list[RuleHit]) -> tuple[str, int, str]:
    score = min(sum(SEVERITY_WEIGHT[h.severity] for h in hits), 100)
    critical   = any(h.severity == "CRITICAL" for h in hits)
    high_count = sum(1 for h in hits if h.severity in ("HIGH", "CRITICAL"))

    if critical or score >= 60:
        return "MALICIOUS", score, "CRITICAL" if score >= 80 else "HIGH"
    elif high_count >= 2 or score >= 30:
        return "SUSPICIOUS", score, "HIGH" if score >= 45 else "MEDIUM"
    elif score > 0:
        return "SUSPICIOUS", score, "LOW"
    else:
        return "BENIGN", score, "LOW"


# ---------------------------------------------
#  EXPLANATION GENERATOR
# ---------------------------------------------

def generate_explanation(classification: str, hits: list[RuleHit], features: dict) -> str:
    file_name = features.get("file_name", "unknown")
    if not hits:
        return (f"No suspicious indicators were found in '{file_name}'. "
                "The archive appears to contain only standard files with no anomalous features.")

    crit = [h for h in hits if h.severity == "CRITICAL"]
    high = [h for h in hits if h.severity == "HIGH"]
    med  = [h for h in hits if h.severity == "MEDIUM"]
    low  = [h for h in hits if h.severity == "LOW"]

    lines = [
        f"The archive '{file_name}' was classified as {classification} "
        f"based on {len(hits)} triggered detection rule(s).\n"
    ]

    for label, group in [("CRITICAL indicators:", crit), ("HIGH severity indicators:", high),
                         ("MEDIUM severity indicators:", med), ("LOW severity indicators:", low)]:
        if group:
            lines.append(label)
            for h in group:
                cve = f" [{h.cve}]" if h.cve else ""
                lines.append(f"  - [{h.rule_id}]{cve} {h.description}")

    cve_hits = [h.cve for h in hits if h.cve]
    if cve_hits:
        lines.append(f"\nMatched CVEs: {', '.join(cve_hits)}")

    return "\n".join(lines)


# ---------------------------------------------
#  MAIN ANALYSIS FUNCTION
# ---------------------------------------------

def analyze(raw: dict) -> DetectionReport:
    features = normalize_features(raw)
    engine = ArchiveRuleEngine(features)
    hits = engine.run_all_rules()
    classification, score, risk_level = classify(hits)
    explanation = generate_explanation(classification, hits, features)

    return DetectionReport(
        file_name=features["file_name"],
        file_path=features.get("file_path", ""),
        classification=classification,
        severity_score=score,
        risk_level=risk_level,
        triggered_rules=hits,
        explanation=explanation,
    )


# ---------------------------------------------
#  OUTPUT FORMATTERS
# ---------------------------------------------

def print_report(report: DetectionReport, features: dict = None):
    sep = "=" * 65
    print(f"\n{sep}")
    print("  ARCHIVE ANALYSIS REPORT")
    print(sep)
    print(f"  File           : {report.file_name}")
    print(f"  Classification : {report.classification}")
    print(f"  Severity Score : {report.severity_score}/100")
    print(f"  Risk Level     : {report.risk_level}")
    print(f"  Timestamp      : {report.analysis_timestamp}")
    if features and features.get("hashes"):
        h = features["hashes"]
        print(f"  MD5            : {h.get('md5', '-')}")
        print(f"  SHA256         : {h.get('sha256', '-')}")
    print(sep)

    if report.triggered_rules:
        print(f"\n  Triggered Rules ({len(report.triggered_rules)}):\n")
        for hit in sorted(report.triggered_rules, key=lambda h: h.rule_id):
            cve = f"  <- {hit.cve}" if hit.cve else ""
            print(f"  [{hit.rule_id}] [{hit.severity:8s}] {hit.description}{cve}")
            print(f"           Evidence: {hit.evidence}")
    else:
        print("\n  No rules triggered.")

    print(f"\n{sep}")
    print("  EXPLANATION")
    print(sep)
    print(report.explanation)
    print(f"{sep}\n")


def report_to_dict(report: DetectionReport, features: dict = None) -> dict:
    result = {
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
            }
            for h in report.triggered_rules
        ],
        "explanation": report.explanation,
    }
    if features and features.get("hashes"):
        result["hashes"] = features["hashes"]
    return result


# ---------------------------------------------
#  CLI
# ---------------------------------------------

def _print_summary(summary: dict, total: int):
    print("\n" + "=" * 65)
    print("  BATCH SUMMARY")
    print("=" * 65)
    print(f"  Total analyzed : {total}")
    print(f"  Benign         : {summary.get('BENIGN', 0)}")
    print(f"  Suspicious     : {summary.get('SUSPICIOUS', 0)}")
    print(f"  Malicious      : {summary.get('MALICIOUS', 0)}")
    print("=" * 65 + "\n")


def _save_combined(summary: dict, results: list, output_path: str):
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump({"summary": summary, "results": results}, out, indent=2, ensure_ascii=False)
    print(f"[+] Combined JSON report saved -> {output_path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Task 2 - Static Rule-Based Archive Detector")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("feature_file", nargs="?",
                       help="Single Task 1 JSON feature file")
    group.add_argument("--batch", metavar="DIR",
                       help="Analyze all JSON files in a directory")
    group.add_argument("--suite", metavar="FILE",
                       help="Analyze a test suite JSON (contains test_samples list)")
    parser.add_argument("--output", metavar="FILE",
                        help="Save combined JSON report to file")
    return parser.parse_args()


def run_single(json_path: str, output_path: str | None = None):
    with open(json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    features = normalize_features(raw)
    report   = analyze(raw)
    print_report(report, features)
    result = report_to_dict(report, features)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as out:
            json.dump(result, out, indent=2, ensure_ascii=False)
        print(f"[+] JSON report saved -> {output_path}")
    return result


def run_suite(suite_path: str, output_path: str | None = None):
    with open(suite_path, "r", encoding="utf-8") as f:
        suite = json.load(f)

    samples = suite.get("test_samples", [])
    if not samples:
        print("[!] No 'test_samples' key found in suite JSON.")
        return

    print(f"[*] Processing {len(samples)} samples from suite...\n")
    summary = {"BENIGN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
    all_results = []

    for i, raw in enumerate(samples, 1):
        clean    = {k: v for k, v in raw.items() if not k.startswith("_")}
        scenario = raw.get("_scenario", f"Sample {i}")
        try:
            features   = normalize_features(clean)
            report_obj = analyze(clean)
            print(f"\n>>> {scenario}")
            print_report(report_obj, features)
            result = report_to_dict(report_obj, features)
            result["scenario"] = scenario
            all_results.append(result)
            summary[result["classification"]] = summary.get(result["classification"], 0) + 1
        except Exception as e:
            print(f"[ERROR] {scenario}: {e}", file=sys.stderr)

    _print_summary(summary, len(all_results))
    if output_path:
        _save_combined(summary, all_results, output_path)


def run_batch(directory: str, output_path: str | None = None):
    json_files = list(Path(directory).glob("*.json"))
    if not json_files:
        print(f"[!] No JSON files found in {directory}")
        return

    print(f"[*] Processing {len(json_files)} files...\n")
    summary = {"BENIGN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
    all_results = []

    for jf in sorted(json_files):
        try:
            with open(jf, "r", encoding="utf-8") as f:
                raw = json.load(f)
            features   = normalize_features(raw)
            report_obj = analyze(raw)
            print_report(report_obj, features)
            result = report_to_dict(report_obj, features)
            all_results.append(result)
            summary[result["classification"]] = summary.get(result["classification"], 0) + 1
        except Exception as e:
            print(f"[ERROR] {jf.name}: {e}", file=sys.stderr)

    _print_summary(summary, len(all_results))
    if output_path:
        _save_combined(summary, all_results, output_path)


def main():
    args = parse_args()
    if args.suite:
        run_suite(args.suite, args.output)
    elif args.batch:
        run_batch(args.batch, args.output)
    else:
        run_single(args.feature_file, args.output)


if __name__ == "__main__":
    main()
