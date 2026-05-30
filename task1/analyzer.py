import os
import hashlib
import math
import zipfile
import tarfile
import py7zr
import rarfile
import re
import magic
import json
import gzip
import bz2
import lzma
import argparse
import sys
from pathlib import Path
from datetime import datetime

class ArchiveAnalyzer:
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.report = {
            "1_basic_info": {},
            "2_archive_metadata": {
                "format": "Unknown",
                "compression_method": "Unknown",
                "compression_ratio": 0.0,
                "password_protected": False,
                "is_split_archive": False,
                "corrupted": False,
                "file_count": 0,
                "comment": None
            },
            "3_internal_files": [],
            "4_security_indicators": {
                "has_executables": False,
                "has_office_macros": False,
                "has_lnk": False,
                "has_nested_archives": False,
                "max_nesting_depth": 0, 
                "double_extensions": [],
                "suspicious_filenames": [],
                "unicode_rtlo_detected": False,
                "extension_mismatches": [],
                "archive_bomb_suspected": False,
                "decoy_and_executable_combo": False
            },
            "5_content_indicators": {
                "urls_found": [],
                "suspicious_commands": []
            }
        }
        
        # Regex Definitions
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.cmd_pattern = re.compile(r'(powershell|cmd\.exe|wscript|cscript|Invoke-WebRequest|IEX|bitsadmin|certutil)', re.IGNORECASE)
        self.split_archive_pattern = re.compile(r'(\.z\d{2}$|\.part\d+\.rar$|\.001$)', re.IGNORECASE)
        
        # Extension Sets
        self.exec_exts = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.js', '.vbs', '.scr', '.jar', '.msi'}
        self.macro_exts = {'.docm', '.xlsm', '.pptm', '.doc', '.xls'}
        self.decoy_exts = {'.pdf', '.docx', '.xlsx', '.txt', '.jpg', '.png'}
        self.archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab', '.iso'}

    def analyze(self):
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")

        self._extract_basic_info()
        self._inspect_archive()
        self._post_process_security_indicators()
        return self.report

    def _extract_basic_info(self):
        """Extracts hashes, MIME type, and basic OS-level file data."""
        data = self.file_path.read_bytes()
        self.report["1_basic_info"] = {
            "file_name": self.file_path.name,
            "file_size": self.file_path.stat().st_size,
            "file_extension": self.file_path.suffix.lower(),
            "mime_type": magic.from_buffer(data[:2048], mime=True),
            "hashes": {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest()
            }
        }
        # Check if the main file is a split archive part
        if self.split_archive_pattern.search(self.file_path.name):
            self.report["2_archive_metadata"]["is_split_archive"] = True

    def _calculate_entropy(self, data):
        """Calculates Shannon entropy to identify high-compression or encrypted payloads."""
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return round(entropy, 2)

    def _inspect_archive(self):
        """Handles format-specific parsing for ZIP, TAR (and GZ/BZ2/XZ), RAR, and 7Z."""
        total_uncompressed, total_compressed = 0, 0
        sec_inds = self.report["4_security_indicators"]

        try:
            # --- ZIP SUPPORT ---
            if zipfile.is_zipfile(self.file_path):
                self.report["2_archive_metadata"]["format"] = "ZIP"
                with zipfile.ZipFile(self.file_path, 'r') as archive:
                    self.report["2_archive_metadata"]["password_protected"] = any(z.flag_bits & 0x1 for z in archive.infolist())
                    self.report["2_archive_metadata"]["file_count"] = len(archive.infolist())
                    self.report["2_archive_metadata"]["comment"] = archive.comment.decode('utf-8', 'ignore') if archive.comment else None
                    
                    for zinfo in archive.infolist():
                        if not zinfo.is_dir():
                            total_uncompressed += zinfo.file_size
                            total_compressed += zinfo.compress_size
                            
                            dt = datetime(*zinfo.date_time).isoformat() if zinfo.date_time else None
                            
                            # Safely read small files for entropy/content scanning
                            content = None
                            if zinfo.file_size < 2 * 1024 * 1024 and not self.report["2_archive_metadata"]["password_protected"]:
                                try: content = archive.read(zinfo)
                                except RuntimeError: pass 

                            self._process_internal_file(zinfo.filename, zinfo.file_size, zinfo.compress_size, dt, content)
            
            # --- TAR SUPPORT (Includes .tar.gz, .tar.bz2, .tar.xz) ---
            elif tarfile.is_tarfile(self.file_path):
                self.report["2_archive_metadata"]["format"] = "TAR"
                with tarfile.open(self.file_path, 'r:*') as archive:
                    members = archive.getmembers()
                    self.report["2_archive_metadata"]["file_count"] = len(members)
                    
                    for member in members:
                        if member.isfile():
                            total_uncompressed += member.size
                            total_compressed += member.size 
                            
                            dt = datetime.fromtimestamp(member.mtime).isoformat() if member.mtime else None
                            
                            content = None
                            if member.size < 2 * 1024 * 1024:
                                try:
                                    f = archive.extractfile(member)
                                    if f: content = f.read()
                                except Exception: pass

                            self._process_internal_file(member.name, member.size, member.size, dt, content)

            # --- RAR SUPPORT ---
            elif rarfile.is_rarfile(self.file_path):
                self.report["2_archive_metadata"]["format"] = "RAR"
                with rarfile.RarFile(self.file_path, 'r') as archive:
                    self.report["2_archive_metadata"]["password_protected"] = archive.needs_password()
                    self.report["2_archive_metadata"]["file_count"] = len(archive.infolist())
                    
                    for rinfo in archive.infolist():
                        if not rinfo.isdir():
                            total_uncompressed += rinfo.file_size
                            total_compressed += rinfo.compress_size
                            
                            dt = datetime(*rinfo.date_time).isoformat() if rinfo.date_time else None
                            self._process_internal_file(rinfo.filename, rinfo.file_size, rinfo.compress_size, dt, None)

            # --- 7Z SUPPORT ---
            elif py7zr.is_7zfile(self.file_path):
                self.report["2_archive_metadata"]["format"] = "7Z"
                with py7zr.SevenZipFile(self.file_path, mode='r') as archive:
                    self.report["2_archive_metadata"]["password_protected"] = archive.password_protected
                    files = archive.list()
                    self.report["2_archive_metadata"]["file_count"] = len(files)
                    
                    for f in files:
                        if not f.is_directory:
                            uncomp = f.uncompressed if f.uncompressed else 0
                            comp = f.compressed if f.compressed else uncomp
                            total_uncompressed += uncomp
                            total_compressed += comp
                            
                            dt = f.creationtime.isoformat() if f.creationtime else None
                            self._process_internal_file(f.filename, uncomp, comp, dt, None)
                            
            # --- STANDALONE GZ / BZ2 / XZ SUPPORT ---
            elif self.file_path.suffix.lower() in {'.gz', '.bz2', '.xz'} and not tarfile.is_tarfile(self.file_path):
                ext = self.file_path.suffix.lower()
                self.report["2_archive_metadata"]["format"] = ext[1:].upper()
                self.report["2_archive_metadata"]["file_count"] = 1
                
                opener = gzip.open if ext == '.gz' else bz2.open if ext == '.bz2' else lzma.open
                try:
                    with opener(self.file_path, 'rb') as archive:
                        content = archive.read()
                        uncomp_size = len(content)
                        comp_size = self.file_path.stat().st_size
                        
                        total_uncompressed += uncomp_size
                        total_compressed += comp_size
                        
                        # Process the payload (the internal file name is just the archive name minus the extension)
                        self._process_internal_file(self.file_path.stem, uncomp_size, comp_size, None, content)
                except Exception:
                    self.report["2_archive_metadata"]["corrupted"] = True
                    
            # Decompression Bomb Check (Ratio > 100x OR Uncompressed > 1GB)
            if total_uncompressed > 0:
                ratio = round(total_uncompressed / total_compressed, 2) if total_compressed > 0 else 1
                self.report["2_archive_metadata"]["compression_ratio"] = ratio
                
                if ratio > 100 or total_uncompressed > (1024 * 1024 * 1024):
                    sec_inds["archive_bomb_suspected"] = True

            # Excessive File Count Check
            if self.report["2_archive_metadata"]["file_count"] > 10000:
                sec_inds["suspicious_filenames"].append("EXCESSIVE_FILE_COUNT")

        except Exception as e:
            self.report["2_archive_metadata"]["corrupted"] = True

    def _process_internal_file(self, filename, uncompressed_size, compressed_size, timestamp, content):
        """Processes individual files within the archive for metadata and security red flags."""
        name_only = Path(filename).name
        ext = Path(filename).suffix.lower()
        parts = name_only.split('.')
        sec_inds = self.report["4_security_indicators"]
        
        # 1. Naming & Unicode Tricks
        is_hidden = name_only.startswith('.')
        if '\u202E' in name_only: 
            sec_inds["unicode_rtlo_detected"] = True
            sec_inds["suspicious_filenames"].append(filename)

        # 2. Double Extension Check (e.g., invoice.pdf.exe)
        has_double_ext = len(parts) > 2 and f".{parts[-2].lower()}" in self.decoy_exts and ext in self.exec_exts
        if has_double_ext: sec_inds["double_extensions"].append(filename)

        # 3. Path/Nesting Depth
        depth = filename.count('/') + filename.count('\\')
        if depth > sec_inds["max_nesting_depth"]:
            sec_inds["max_nesting_depth"] = depth

        # 4. Standard Threat Indicators
        if ext in self.exec_exts: sec_inds["has_executables"] = True
        if ext in self.macro_exts: sec_inds["has_office_macros"] = True
        if ext == '.lnk': sec_inds["has_lnk"] = True
        if ext in self.archive_exts: sec_inds["has_nested_archives"] = True

        file_data = {
            "internal_path": filename,
            "file_name": name_only,
            "file_extension": ext,
            "compressed_size": compressed_size,
            "uncompressed_size": uncompressed_size,
            "timestamp": timestamp,
            "is_executable_or_script": ext in self.exec_exts,
            "is_hidden": is_hidden,
            "has_double_extension": has_double_ext,
            "entropy": 0
        }

        # 5. Content Analysis (if safely read in memory)
        if content:
            file_data["entropy"] = self._calculate_entropy(content)
            
            # Check Extension Mismatch via MIME
            internal_mime = magic.from_buffer(content[:2048], mime=True)
            if ext in {'.pdf', '.jpg', '.png', '.txt'} and "application/x-dosexec" in internal_mime:
                sec_inds["extension_mismatches"].append(filename)

            # Regex for text-based scripts
            if ext in {'.txt', '.bat', '.ps1', '.vbs', '.js', '.html', '.hta'}:
                decoded = content.decode('utf-8', 'ignore')
                self.report["5_content_indicators"]["urls_found"].extend(self.url_pattern.findall(decoded))
                self.report["5_content_indicators"]["suspicious_commands"].extend(self.cmd_pattern.findall(decoded))

        self.report["3_internal_files"].append(file_data)

    def _post_process_security_indicators(self):
        """Cross-references findings (e.g., looking for a decoy PDF + an EXE in the same archive)."""
        has_decoy = any(f["file_extension"] in self.decoy_exts for f in self.report["3_internal_files"])
        has_exec = self.report["4_security_indicators"]["has_executables"]
        
        if has_decoy and has_exec:
            self.report["4_security_indicators"]["decoy_and_executable_combo"] = True

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Task 1: Archive Analyzer Extractor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("file", nargs="?", help="Path to a single archive file")
    group.add_argument("--batch", metavar="DIR", help="Directory to scan recursively for archives")
    parser.add_argument("--outdir", default="reports", help="Directory to save the JSON reports")
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    out_path = Path(args.outdir)
    out_path.mkdir(parents=True, exist_ok=True)

    def run_analysis(target_path):
        try:
            analyzer = ArchiveAnalyzer(target_path)
            result = analyzer.analyze()
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = target_path.stem
            output_filename = out_path / f"{base_name}_{timestamp}.json"
            
            with open(output_filename, 'w') as f:
                json.dump(result, f, indent=4)
            print(f"[+] Analyzed: {target_path.name} -> {output_filename.name}")
        except Exception as e:
            print(f"[-] Error processing {target_path.name}: {e}")

    if args.batch:
        scan_dir = Path(args.batch)
        print(f"[*] Starting batch analysis recursively on: {scan_dir}")
        for file_path in scan_dir.rglob("*"):
            if file_path.is_file():
                run_analysis(file_path)
        print(f"[*] Batch complete. All reports safely stored in '{args.outdir}'")
    else:
        run_analysis(Path(args.file))
        