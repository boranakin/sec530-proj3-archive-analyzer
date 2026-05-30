"""
SEC530 - Project 3: Smart Compression Archive Analyzer
Task 3: LLM-Based Analysis of Extracted Archive Data

Feeds Task 1 JSON output to an LLM and produces an HTML analyst report.

Supported providers:
  --provider claude   → Anthropic API  (default)
  --provider openai   → OpenAI API
  --provider ollama   → Local Ollama (no key needed)

Usage:
    python task3_llm_analyzer.py <task1_json> --api-key YOUR_KEY
    python task3_llm_analyzer.py <task1_json> --api-key YOUR_KEY --output report.html
    python task3_llm_analyzer.py <task1_json> --provider openai --api-key sk-...
    python task3_llm_analyzer.py <task1_json> --provider ollama --model llama3
    python task3_llm_analyzer.py --batch <dir_of_jsons> --api-key YOUR_KEY
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import textwrap
from datetime import datetime
from pathlib import Path

import requests

# ──────────────────────────────────────────────────────────────
#  PROVIDER CONFIGURATION
# ──────────────────────────────────────────────────────────────

PROVIDERS = {
    "claude": {
        "url":     "https://api.anthropic.com/v1/messages",
        "model":   "claude-sonnet-4-20250514",
        "headers": lambda key: {
            "x-api-key":         key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        },
        "build_body": lambda model, system, user, max_tokens: {
            "model":      model,
            "max_tokens": max_tokens,
            "system":     system,
            "messages":   [{"role": "user", "content": user}],
        },
        "extract_text": lambda r: r["content"][0]["text"],
    },
    "openai": {
        "url":     "https://api.openai.com/v1/chat/completions",
        "model":   "gpt-4o",
        "headers": lambda key: {
            "Authorization": f"Bearer {key}",
            "Content-Type":  "application/json",
        },
        "build_body": lambda model, system, user, max_tokens: {
            "model":      model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system",  "content": system},
                {"role": "user",    "content": user},
            ],
        },
        "extract_text": lambda r: r["choices"][0]["message"]["content"],
    },
    # Gemini — OpenAI-compatible endpoint (google AI Studio key)
    # Docs: https://ai.google.dev/gemini-api/docs/openai
    "gemini": {
        "url":   "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "model": "gemini-2.0-flash",
        "headers": lambda key: {
            "Authorization": f"Bearer {key}",
            "Content-Type":  "application/json",
        },
        "build_body": lambda model, system, user, max_tokens: {
            "model":      model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        },
        "extract_text": lambda r: r["choices"][0]["message"]["content"],
    },
    "ollama": {
        "url":     "http://localhost:11434/api/chat",
        "model":   "llama3",
        "headers": lambda key: {"Content-Type": "application/json"},
        "build_body": lambda model, system, user, max_tokens: {
            "model":  model,
            "stream": False,
            "messages": [
                {"role": "system",  "content": system},
                {"role": "user",    "content": user},
            ],
        },
        "extract_text": lambda r: r["message"]["content"],
    },
}

# ──────────────────────────────────────────────────────────────
#  SYSTEM PROMPT
# ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert malware analyst and cybersecurity researcher specializing in
archive-based threats. Your task is to analyze structured metadata extracted from a compressed
archive file and produce a thorough, professional threat-intelligence report.

You will receive JSON metadata from a static analysis tool (Task 1). You must:

1. CLASSIFY the archive as BENIGN, SUSPICIOUS, or MALICIOUS with a confidence percentage.

2. EXPLAIN your reasoning step by step, referencing specific fields from the metadata.

3. IDENTIFY any known CVEs or vulnerability patterns that the archive's structure matches,
   covering the period 2000–2025. Focus on:
   - Archive parser vulnerabilities (WinRAR, 7-Zip, libarchive, Info-ZIP, Python tarfile…)
   - Path traversal / Zip Slip attacks
   - Decompression bombs
   - Unicode / RTLO / double-extension filename tricks
   - Encrypted archives hiding payloads
   - Macro-enabled Office documents
   - Shortcut (.lnk) abuse
   - Supply-chain / trojanized archive patterns

4. LIST indicators of compromise (IOCs) or suspicious features observed.

5. RECOMMEND analyst next steps.

Output format — respond with a JSON object only, no markdown fences, no preamble:
{
  "classification": "BENIGN | SUSPICIOUS | MALICIOUS",
  "confidence":     0-100,
  "risk_level":     "LOW | MEDIUM | HIGH | CRITICAL",
  "severity_score": 0-100,
  "summary":        "2-3 sentence executive summary",
  "reasoning": [
    {"step": 1, "finding": "...", "significance": "LOW|MEDIUM|HIGH|CRITICAL"}
  ],
  "cve_matches": [
    {"cve_id": "CVE-XXXX-XXXXX", "description": "...", "matched_because": "..."}
  ],
  "iocs": [
    {"type": "filename|url|hash|pattern|string", "value": "...", "note": "..."}
  ],
  "next_steps": ["...", "..."],
  "analyst_notes": "longer free-text analysis paragraph"
}"""

# ──────────────────────────────────────────────────────────────
#  FEATURE SUMMARIZER  (task1 json → compact prompt text)
# ──────────────────────────────────────────────────────────────

def build_user_prompt(raw: dict) -> str:
    """Convert Task 1 JSON into a focused, token-efficient prompt."""

    basic   = raw.get("1_basic_info", {})
    meta    = raw.get("2_archive_metadata", {})
    files   = raw.get("3_internal_files", [])
    sec     = raw.get("4_security_indicators", {})
    content = raw.get("5_content_indicators", {})

    lines = [
        "=== ARCHIVE METADATA (Task 1 Extractor Output) ===\n",
        f"File name   : {basic.get('file_name', 'unknown')}",
        f"File size   : {basic.get('file_size', 0):,} bytes",
        f"MIME type   : {basic.get('mime_type', '')}",
        f"MD5         : {basic.get('hashes', {}).get('md5', '-')}",
        f"SHA256      : {basic.get('hashes', {}).get('sha256', '-')}",
        "",
        f"Format      : {meta.get('format', 'unknown')}",
        f"Compression : {meta.get('compression_method', 'unknown')}",
        f"Ratio       : {meta.get('compression_ratio', 0)}x",
        f"Encrypted   : {meta.get('password_protected', False)}",
        f"Split       : {meta.get('is_split_archive', False)}",
        f"Corrupted   : {meta.get('corrupted', False)}",
        f"File count  : {meta.get('file_count', len(files))}",
        f"Comment     : {meta.get('comment') or '(none)'}",
        "",
        "--- Internal Files ---",
    ]

    for i, fi in enumerate(files[:50], 1):   # cap at 50 for token budget
        entropy = fi.get("entropy", 0)
        lines.append(
            f"  [{i:02d}] {fi.get('internal_path') or fi.get('file_name', '?')}"
            f"  | {fi.get('uncompressed_size', 0):,}B"
            f"  | entropy={entropy:.2f}"
            f"  | mime={fi.get('detected_mime', '?')}"
            f"  | hidden={fi.get('is_hidden', False)}"
            f"  | double_ext={fi.get('has_double_extension', False)}"
        )

    if len(files) > 50:
        lines.append(f"  ... ({len(files) - 50} more files truncated)")

    lines += [
        "",
        "--- Security Indicators (pre-computed) ---",
        f"  has_executables          : {sec.get('has_executables', False)}",
        f"  has_office_macros        : {sec.get('has_office_macros', False)}",
        f"  has_lnk                  : {sec.get('has_lnk', False)}",
        f"  has_nested_archives      : {sec.get('has_nested_archives', False)}",
        f"  max_nesting_depth        : {sec.get('max_nesting_depth', 0)}",
        f"  unicode_rtlo_detected    : {sec.get('unicode_rtlo_detected', False)}",
        f"  archive_bomb_suspected   : {sec.get('archive_bomb_suspected', False)}",
        f"  decoy_and_executable     : {sec.get('decoy_and_executable_combo', False)}",
        f"  double_extensions        : {sec.get('double_extensions', [])}",
        f"  extension_mismatches     : {sec.get('extension_mismatches', [])}",
        f"  suspicious_filenames     : {sec.get('suspicious_filenames', [])}",
    ]

    urls  = content.get("urls_found", [])
    cmds  = content.get("suspicious_commands", [])

    if urls:
        lines.append(f"\n  URLs found ({len(urls)}): {urls[:10]}")
    if cmds:
        lines.append(f"  Suspicious commands ({len(cmds)}): {cmds[:10]}")

    lines.append("\n=== END OF METADATA ===")
    lines.append("\nAnalyze the above and return your report as the JSON format specified.")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────
#  LLM CLIENT
# ──────────────────────────────────────────────────────────────

class LLMClient:

    def __init__(self, provider: str, api_key: str, model: str | None, max_tokens: int):
        if provider not in PROVIDERS:
            raise ValueError(f"Unknown provider '{provider}'. Choose: {list(PROVIDERS)}")

        self.cfg        = PROVIDERS[provider]
        self.api_key    = api_key or ""
        self.model      = model or self.cfg["model"]
        self.max_tokens = max_tokens

    def analyze(self, user_prompt: str) -> dict:
        """Send prompt to LLM and return parsed JSON response."""
        headers = self.cfg["headers"](self.api_key)
        body    = self.cfg["build_body"](
            self.model, SYSTEM_PROMPT, user_prompt, self.max_tokens
        )

        try:
            resp = requests.post(
                self.cfg["url"],
                headers=headers,
                json=body,
                timeout=120,
            )
            resp.raise_for_status()
        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "?"
            msg  = ""
            try:
                msg = exc.response.json()
            except Exception:
                pass
            raise RuntimeError(f"HTTP {code}: {msg}") from exc
        except requests.RequestException as exc:
            raise RuntimeError(f"Request failed: {exc}") from exc

        raw_text = self.cfg["extract_text"](resp.json())

        # Strip possible markdown fences
        clean = raw_text.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1]
        if clean.endswith("```"):
            clean = clean.rsplit("```", 1)[0]
        clean = clean.strip()

        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            # Return raw text wrapped so we can still render it
            return {
                "classification": "UNKNOWN",
                "confidence":     0,
                "risk_level":     "UNKNOWN",
                "severity_score": 0,
                "summary":        "LLM returned non-JSON response.",
                "reasoning":      [],
                "cve_matches":    [],
                "iocs":           [],
                "next_steps":     [],
                "analyst_notes":  raw_text,
            }


# ──────────────────────────────────────────────────────────────
#  HTML REPORT GENERATOR
# ──────────────────────────────────────────────────────────────

def _badge_color(level: str) -> str:
    return {
        "CRITICAL": "#c0392b",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#2980b9",
        "LOW":      "#27ae60",
        "MALICIOUS":  "#c0392b",
        "SUSPICIOUS": "#e67e22",
        "BENIGN":     "#27ae60",
        "UNKNOWN":    "#7f8c8d",
    }.get(level.upper(), "#7f8c8d")


def _sig_color(sig: str) -> str:
    return {
        "CRITICAL": "#fdecea",
        "HIGH":     "#fef3e2",
        "MEDIUM":   "#e8f4fd",
        "LOW":      "#eafaf1",
    }.get(sig.upper(), "#f5f5f5")


def generate_html_report(
    file_name: str,
    task1_raw: dict,
    llm_result: dict,
    provider: str,
    model: str,
) -> str:
    cls   = llm_result.get("classification", "UNKNOWN").upper()
    conf  = llm_result.get("confidence", 0)
    risk  = llm_result.get("risk_level", "UNKNOWN").upper()
    score = llm_result.get("severity_score", 0)
    summ  = llm_result.get("summary", "")
    notes = llm_result.get("analyst_notes", "")

    reasoning  = llm_result.get("reasoning", [])
    cve_matches = llm_result.get("cve_matches", [])
    iocs       = llm_result.get("iocs", [])
    next_steps = llm_result.get("next_steps", [])

    cls_color  = _badge_color(cls)
    risk_color = _badge_color(risk)

    # ── Reasoning rows ────────────────────────
    reasoning_rows = ""
    for r in reasoning:
        sig = r.get("significance", "LOW").upper()
        bg  = _sig_color(sig)
        sc  = _badge_color(sig)
        reasoning_rows += f"""
        <tr style="background:{bg}">
          <td style="padding:10px 14px;font-weight:600;color:#2c3e50;width:36px;text-align:center">
            {r.get('step', '')}
          </td>
          <td style="padding:10px 14px;color:#2c3e50;line-height:1.6">
            {r.get('finding', '')}
          </td>
          <td style="padding:10px 14px;text-align:center;white-space:nowrap">
            <span style="background:{sc};color:#fff;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700">
              {sig}
            </span>
          </td>
        </tr>"""

    # ── CVE rows ──────────────────────────────
    cve_rows = ""
    for c in cve_matches:
        cve_id = c.get("cve_id", "")
        cve_rows += f"""
        <tr>
          <td style="padding:10px 14px">
            <a href="https://nvd.nist.gov/vuln/detail/{cve_id}"
               target="_blank"
               style="font-family:'Courier New',monospace;font-weight:700;color:#c0392b;text-decoration:none">
              {cve_id}
            </a>
          </td>
          <td style="padding:10px 14px;color:#34495e">{c.get('description','')}</td>
          <td style="padding:10px 14px;color:#7f8c8d;font-style:italic">{c.get('matched_because','')}</td>
        </tr>"""

    # ── IOC rows ─────────────────────────────
    ioc_rows = ""
    for ioc in iocs:
        itype = ioc.get("type", "")
        type_colors = {
            "filename": "#9b59b6", "url": "#e74c3c", "hash": "#2c3e50",
            "pattern": "#e67e22", "string": "#16a085",
        }
        tc = type_colors.get(itype.lower(), "#7f8c8d")
        ioc_rows += f"""
        <tr>
          <td style="padding:10px 14px;text-align:center">
            <span style="background:{tc};color:#fff;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600">
              {itype}
            </span>
          </td>
          <td style="padding:10px 14px;font-family:'Courier New',monospace;font-size:13px;color:#2c3e50;word-break:break-all">
            {ioc.get('value','')}
          </td>
          <td style="padding:10px 14px;color:#7f8c8d">{ioc.get('note','')}</td>
        </tr>"""

    # ── Next steps ───────────────────────────
    steps_html = "".join(
        f'<li style="padding:6px 0;color:#2c3e50;line-height:1.6">{s}</li>'
        for s in next_steps
    )

    # ── Internal file table (top 30) ─────────
    files = task1_raw.get("3_internal_files", [])
    file_rows = ""
    for fi in files[:30]:
        ent = float(fi.get("entropy", 0))
        ent_color = "#c0392b" if ent >= 7.5 else ("#e67e22" if ent >= 6.0 else "#27ae60")
        double = "⚠ double-ext" if fi.get("has_double_extension") else ""
        hidden = "⚠ hidden" if fi.get("is_hidden") else ""
        warn = f'<span style="color:#e67e22;font-size:11px;margin-left:6px">{double} {hidden}</span>'
        file_rows += f"""
        <tr>
          <td style="padding:8px 12px;font-family:'Courier New',monospace;font-size:12px;color:#2c3e50;word-break:break-all">
            {fi.get('internal_path') or fi.get('file_name','?')}{warn}
          </td>
          <td style="padding:8px 12px;color:#7f8c8d;text-align:right">
            {fi.get('uncompressed_size',0):,}
          </td>
          <td style="padding:8px 12px;text-align:center">
            <span style="color:{ent_color};font-weight:700">{ent:.2f}</span>
          </td>
          <td style="padding:8px 12px;color:#7f8c8d;font-size:12px">{fi.get('detected_mime','')}</td>
        </tr>"""
    if len(files) > 30:
        file_rows += f"""
        <tr>
          <td colspan="4" style="padding:8px 12px;color:#95a5a6;font-style:italic;text-align:center">
            … {len(files)-30} more files not shown
          </td>
        </tr>"""

    # ── Basic info ───────────────────────────
    basic = task1_raw.get("1_basic_info", {})
    meta  = task1_raw.get("2_archive_metadata", {})
    sec   = task1_raw.get("4_security_indicators", {})

    def flag_row(label, value):
        v = str(value)
        color = "#c0392b" if v == "True" else ("#27ae60" if v == "False" else "#2c3e50")
        icon  = "✗" if v == "True" else ("✓" if v == "False" else "")
        return (f'<tr><td style="padding:6px 14px;color:#7f8c8d;width:220px">{label}</td>'
                f'<td style="padding:6px 14px;color:{color};font-weight:600">{icon} {v}</td></tr>')

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Gauge SVG ─────────────────────────────
    # Score arc: 0-100 mapped to 0-180 degrees (semicircle)
    angle   = score * 1.8        # degrees
    rad     = 3.14159 / 180
    cx, cy, r = 100, 100, 80
    end_x = cx + r * (-1 * __import__('math').cos(angle * rad))
    end_y = cy - r * __import__('math').sin(angle * rad) * (-1)
    end_x = cx - r * __import__('math').cos((180 - angle) * rad)
    end_y = cy + r * __import__('math').sin((180 - angle) * rad)
    large = 1 if angle > 180 else 0

    gauge_color = "#c0392b" if score >= 60 else ("#e67e22" if score >= 30 else "#27ae60")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Archive Analysis — {file_name}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'IBM Plex Sans', sans-serif;
    background: #0d1117;
    color: #e6edf3;
    min-height: 100vh;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #161b22 0%, #1a1f29 100%);
    border-bottom: 1px solid #30363d;
    padding: 32px 48px;
    display: flex;
    align-items: center;
    gap: 24px;
  }}
  .header-icon {{
    width: 56px; height: 56px;
    background: {cls_color};
    border-radius: 14px;
    display: flex; align-items: center; justify-content: center;
    font-size: 26px; flex-shrink: 0;
  }}
  .header-title {{ font-size: 22px; font-weight: 700; color: #e6edf3; line-height: 1.2; }}
  .header-sub {{ font-size: 13px; color: #8b949e; margin-top: 4px;
                 font-family: 'IBM Plex Mono', monospace; }}
  .header-meta {{ margin-left: auto; text-align: right; font-size: 12px; color: #8b949e; line-height: 1.8; }}

  /* ── Layout ── */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 48px 64px; }}

  /* ── Cards ── */
  .card {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    margin-bottom: 24px;
    overflow: hidden;
  }}
  .card-header {{
    padding: 16px 24px;
    border-bottom: 1px solid #30363d;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    color: #8b949e;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .card-body {{ padding: 24px; }}

  /* ── Verdict banner ── */
  .verdict {{
    background: linear-gradient(135deg, {cls_color}22, {cls_color}11);
    border: 1px solid {cls_color}66;
    border-radius: 12px;
    padding: 28px 32px;
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 24px;
    align-items: center;
    margin-bottom: 24px;
  }}
  .verdict-label {{
    font-size: 11px; font-weight: 700; letter-spacing: .1em;
    text-transform: uppercase; color: #8b949e; margin-bottom: 8px;
  }}
  .verdict-cls {{
    font-size: 42px; font-weight: 700; color: {cls_color};
    font-family: 'IBM Plex Mono', monospace; line-height: 1;
  }}
  .verdict-conf {{
    font-size: 14px; color: #8b949e; margin-top: 8px;
  }}
  .verdict-summary {{
    font-size: 14px; color: #c9d1d9; line-height: 1.7;
    margin-top: 16px; padding-top: 16px;
    border-top: 1px solid #30363d;
  }}

  /* ── Score gauge ── */
  .gauge-wrap {{ text-align: center; }}
  .gauge-score {{
    font-size: 36px; font-weight: 700;
    color: {gauge_color};
    font-family: 'IBM Plex Mono', monospace;
  }}
  .gauge-label {{ font-size: 11px; color: #8b949e; margin-top: 4px; }}

  /* ── Metrics row ── */
  .metrics {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }}
  .metric {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
  }}
  .metric-val {{ font-size: 24px; font-weight: 700; font-family: 'IBM Plex Mono', monospace; }}
  .metric-lbl {{ font-size: 11px; color: #8b949e; margin-top: 6px; letter-spacing: .05em; text-transform: uppercase; }}

  /* ── Tables ── */
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    background: #0d1117;
    padding: 10px 14px;
    text-align: left;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .05em;
    text-transform: uppercase;
    color: #8b949e;
    border-bottom: 1px solid #30363d;
  }}
  td {{ border-bottom: 1px solid #21262d; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1c2128; }}

  /* ── Analyst notes ── */
  .analyst-notes {{
    background: #0d1117;
    border-left: 3px solid {cls_color};
    border-radius: 0 8px 8px 0;
    padding: 20px 24px;
    font-size: 14px;
    line-height: 1.8;
    color: #c9d1d9;
    white-space: pre-wrap;
  }}

  /* ── Next steps ── */
  .steps-list {{
    list-style: none;
    counter-reset: steps;
  }}
  .steps-list li {{
    counter-increment: steps;
    padding: 10px 0 10px 40px;
    position: relative;
    border-bottom: 1px solid #21262d;
    font-size: 14px;
    line-height: 1.6;
    color: #c9d1d9;
  }}
  .steps-list li:last-child {{ border-bottom: none; }}
  .steps-list li::before {{
    content: counter(steps);
    position: absolute; left: 0;
    background: {cls_color}33;
    color: {cls_color};
    width: 26px; height: 26px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 700;
    top: 10px;
  }}

  /* ── Footer ── */
  .footer {{
    text-align: center;
    padding: 32px;
    font-size: 12px;
    color: #484f58;
    border-top: 1px solid #21262d;
    margin-top: 48px;
  }}
</style>
</head>
<body>

<!-- ═══ HEADER ═══════════════════════════════════════════════ -->
<div class="header">
  <div class="header-icon">
    {'🔴' if cls == 'MALICIOUS' else ('🟡' if cls == 'SUSPICIOUS' else '🟢')}
  </div>
  <div>
    <div class="header-title">Archive Threat Analysis Report</div>
    <div class="header-sub">{file_name}</div>
  </div>
  <div class="header-meta">
    Generated: {now}<br>
    Model: {model}<br>
    Provider: {provider}
  </div>
</div>

<div class="container">

<!-- ═══ VERDICT ══════════════════════════════════════════════ -->
<div class="verdict">
  <div>
    <div class="verdict-label">Classification</div>
    <div class="verdict-cls">{cls}</div>
    <div class="verdict-conf">Confidence: <strong>{conf}%</strong></div>
    <div class="verdict-summary">{summ}</div>
  </div>
  <div class="gauge-wrap">
    <svg width="160" height="100" viewBox="0 0 200 120">
      <!-- background arc -->
      <path d="M 20 100 A 80 80 0 0 1 180 100"
            fill="none" stroke="#21262d" stroke-width="16" stroke-linecap="round"/>
      <!-- score arc -->
      <path d="M 20 100 A 80 80 0 {large} 1 {end_x:.1f} {end_y:.1f}"
            fill="none" stroke="{gauge_color}" stroke-width="16"
            stroke-linecap="round"/>
    </svg>
    <div class="gauge-score">{score}</div>
    <div class="gauge-label">SEVERITY SCORE / 100</div>
  </div>
</div>

<!-- ═══ METRICS ══════════════════════════════════════════════ -->
<div class="metrics">
  <div class="metric">
    <div class="metric-val" style="color:{risk_color}">{risk}</div>
    <div class="metric-lbl">Risk Level</div>
  </div>
  <div class="metric">
    <div class="metric-val" style="color:#58a6ff">{len(cve_matches)}</div>
    <div class="metric-lbl">CVE Matches</div>
  </div>
  <div class="metric">
    <div class="metric-val" style="color:#f0883e">{len(iocs)}</div>
    <div class="metric-lbl">IOCs Found</div>
  </div>
  <div class="metric">
    <div class="metric-val" style="color:#3fb950">{len(reasoning)}</div>
    <div class="metric-lbl">Findings</div>
  </div>
</div>

<!-- ═══ ARCHIVE INFO ══════════════════════════════════════════ -->
<div class="card">
  <div class="card-header">📦 Archive Metadata</div>
  <div class="card-body" style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
    <table>
      <tr><th colspan="2">Basic Information</th></tr>
      <tr><td style="padding:6px 14px;color:#8b949e;width:160px">File name</td>
          <td style="padding:6px 14px;color:#e6edf3;font-family:'IBM Plex Mono',monospace;font-size:12px">{basic.get('file_name','')}</td></tr>
      <tr><td style="padding:6px 14px;color:#8b949e">File size</td>
          <td style="padding:6px 14px;color:#e6edf3">{basic.get('file_size',0):,} bytes</td></tr>
      <tr><td style="padding:6px 14px;color:#8b949e">MIME type</td>
          <td style="padding:6px 14px;color:#e6edf3">{basic.get('mime_type','')}</td></tr>
      <tr><td style="padding:6px 14px;color:#8b949e">Format</td>
          <td style="padding:6px 14px;color:#e6edf3">{meta.get('format','')}</td></tr>
      <tr><td style="padding:6px 14px;color:#8b949e">Compression</td>
          <td style="padding:6px 14px;color:#e6edf3">{meta.get('compression_method','')}</td></tr>
      <tr><td style="padding:6px 14px;color:#8b949e">Ratio</td>
          <td style="padding:6px 14px;color:#e6edf3">{meta.get('compression_ratio',0)}x</td></tr>
      <tr><td style="padding:6px 14px;color:#8b949e">File count</td>
          <td style="padding:6px 14px;color:#e6edf3">{meta.get('file_count', len(task1_raw.get('3_internal_files',[])))}</td></tr>
    </table>
    <table>
      <tr><th colspan="2">Security Flags</th></tr>
      {flag_row("Encrypted", meta.get("password_protected", False))}
      {flag_row("Corrupted", meta.get("corrupted", False))}
      {flag_row("Split archive", meta.get("is_split_archive", False))}
      {flag_row("Has executables", sec.get("has_executables", False))}
      {flag_row("Has LNK shortcuts", sec.get("has_lnk", False))}
      {flag_row("Has office macros", sec.get("has_office_macros", False))}
      {flag_row("Has nested archives", sec.get("has_nested_archives", False))}
      {flag_row("Archive bomb", sec.get("archive_bomb_suspected", False))}
      {flag_row("RTLO detected", sec.get("unicode_rtlo_detected", False))}
      {flag_row("Decoy + executable", sec.get("decoy_and_executable_combo", False))}
    </table>
  </div>
</div>

<!-- ═══ REASONING ═════════════════════════════════════════════ -->
<div class="card">
  <div class="card-header">🔍 LLM Analysis — Step-by-Step Findings</div>
  <table>
    <thead><tr>
      <th style="width:50px">#</th>
      <th>Finding</th>
      <th style="width:110px;text-align:center">Significance</th>
    </tr></thead>
    <tbody style="color:#c9d1d9">{reasoning_rows or '<tr><td colspan="3" style="padding:16px;text-align:center;color:#484f58">No reasoning steps returned.</td></tr>'}</tbody>
  </table>
</div>

<!-- ═══ CVE MATCHES ═══════════════════════════════════════════ -->
<div class="card">
  <div class="card-header">🛡️ CVE Matches (2000–2025)</div>
  <table>
    <thead><tr>
      <th style="width:160px">CVE ID</th>
      <th>Description</th>
      <th>Matched Because</th>
    </tr></thead>
    <tbody style="color:#c9d1d9">{cve_rows or '<tr><td colspan="3" style="padding:16px;text-align:center;color:#484f58">No CVE matches identified.</td></tr>'}</tbody>
  </table>
</div>

<!-- ═══ IOCs ══════════════════════════════════════════════════ -->
<div class="card">
  <div class="card-header">⚠️ Indicators of Compromise</div>
  <table>
    <thead><tr>
      <th style="width:110px;text-align:center">Type</th>
      <th>Value</th>
      <th>Note</th>
    </tr></thead>
    <tbody style="color:#c9d1d9">{ioc_rows or '<tr><td colspan="3" style="padding:16px;text-align:center;color:#484f58">No IOCs identified.</td></tr>'}</tbody>
  </table>
</div>

<!-- ═══ INTERNAL FILES ════════════════════════════════════════ -->
<div class="card">
  <div class="card-header">📁 Internal File Listing</div>
  <table>
    <thead><tr>
      <th>Path / Filename</th>
      <th style="width:120px;text-align:right">Size (bytes)</th>
      <th style="width:90px;text-align:center">Entropy</th>
      <th style="width:200px">MIME Type</th>
    </tr></thead>
    <tbody style="color:#c9d1d9">{file_rows or '<tr><td colspan="4" style="padding:16px;text-align:center;color:#484f58">No file listing available.</td></tr>'}</tbody>
  </table>
</div>

<!-- ═══ ANALYST NOTES ═════════════════════════════════════════ -->
<div class="card">
  <div class="card-header">📝 Analyst Notes</div>
  <div class="card-body">
    <div class="analyst-notes">{notes or 'No additional analyst notes.'}</div>
  </div>
</div>

<!-- ═══ NEXT STEPS ════════════════════════════════════════════ -->
<div class="card">
  <div class="card-header">✅ Recommended Next Steps</div>
  <div class="card-body">
    <ol class="steps-list">{steps_html or '<li>No recommendations provided.</li>'}</ol>
  </div>
</div>

</div><!-- /container -->

<div class="footer">
  SEC530 — Smart Compression Archive Analyzer &nbsp;·&nbsp;
  Task 3: LLM-Based Analysis &nbsp;·&nbsp;
  Generated {now}
</div>

</body>
</html>"""

    return html


# ──────────────────────────────────────────────────────────────
#  RUNNERS
# ──────────────────────────────────────────────────────────────

def run_single(
    json_path: str,
    client: LLMClient,
    provider: str,
    model: str,
    output_path: str,
) -> None:
    print(f"[*] Loading  : {json_path}")
    with open(json_path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    file_name = raw.get("1_basic_info", {}).get("file_name", Path(json_path).stem)
    print(f"[*] File     : {file_name}")
    print(f"[*] Querying : {provider} / {model}")

    prompt = build_user_prompt(raw)

    t0 = time.time()
    result = client.analyze(prompt)
    elapsed = time.time() - t0

    cls   = result.get("classification", "UNKNOWN")
    score = result.get("severity_score", 0)
    print(f"[✓] Result   : {cls}  score={score}/100  ({elapsed:.1f}s)")
    print(f"    CVEs     : {len(result.get('cve_matches', []))} matched")
    print(f"    IOCs     : {len(result.get('iocs', []))} found")

    html = generate_html_report(file_name, raw, result, provider, model)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"[+] Report   : {output_path}")


def run_batch(
    directory: str,
    client: LLMClient,
    provider: str,
    model: str,
    output_dir: str,
) -> None:
    json_files = sorted(Path(directory).glob("*.json"))
    if not json_files:
        print(f"[!] No JSON files in {directory}")
        return

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    print(f"[*] Batch mode: {len(json_files)} files → {output_dir}/\n")

    for i, jf in enumerate(json_files, 1):
        print(f"[{i}/{len(json_files)}] {jf.name}")
        out = str(Path(output_dir) / (jf.stem + "_llm_report.html"))
        try:
            run_single(str(jf), client, provider, model, out)
        except Exception as exc:
            print(f"  [ERROR] {exc}", file=sys.stderr)
        print()
        time.sleep(1)


# ──────────────────────────────────────────────────────────────
#  SUITE RUNNER + COMBINED HTML REPORT
# ──────────────────────────────────────────────────────────────

def _cls_icon(cls: str) -> str:
    return {"MALICIOUS": "🔴", "SUSPICIOUS": "🟡", "BENIGN": "🟢"}.get(cls.upper(), "⚪")

def _cls_color(cls: str) -> str:
    return {"MALICIOUS": "#c0392b", "SUSPICIOUS": "#e67e22", "BENIGN": "#27ae60"}.get(cls.upper(), "#7f8c8d")

def _risk_color(r: str) -> str:
    return {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#2980b9", "LOW": "#27ae60"}.get(r.upper(), "#7f8c8d")

def _sig_bg(s: str) -> str:
    return {"CRITICAL": "#3d1a1a", "HIGH": "#3d2a0a", "MEDIUM": "#0a2035", "LOW": "#0a2a0a"}.get(s.upper(), "#1c2128")

def _sig_col(s: str) -> str:
    return {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#3498db", "LOW": "#2ecc71"}.get(s.upper(), "#8b949e")


def generate_suite_html(
    entries: list[dict],   # list of {scenario, file_name, raw, result, error}
    provider: str,
    model: str,
) -> str:
    """Build a single self-contained HTML report for all suite samples."""

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total  = len(entries)
    mal    = sum(1 for e in entries if e.get("result", {}).get("classification","").upper() == "MALICIOUS")
    sus    = sum(1 for e in entries if e.get("result", {}).get("classification","").upper() == "SUSPICIOUS")
    ben    = sum(1 for e in entries if e.get("result", {}).get("classification","").upper() == "BENIGN")
    errors = sum(1 for e in entries if e.get("error"))

    # ── Sidebar items ──────────────────────────────────────────
    sidebar_items = ""
    for i, e in enumerate(entries):
        res  = e.get("result", {})
        cls  = res.get("classification", "ERROR").upper()
        score = res.get("severity_score", 0)
        icon  = _cls_icon(cls)
        col   = _cls_color(cls)
        fname = e.get("file_name", "unknown")
        scenario = e.get("scenario", f"Sample {i+1}")
        # shorten scenario label
        label = scenario.split(":", 1)[-1].strip() if ":" in scenario else scenario
        sidebar_items += f"""
        <div class="sidebar-item" id="nav-{i}" onclick="showPanel({i})">
          <div class="si-icon">{icon}</div>
          <div class="si-body">
            <div class="si-name" title="{fname}">{fname}</div>
            <div class="si-label" title="{label}">{label}</div>
          </div>
          <div class="si-score" style="color:{col}">{score}</div>
        </div>"""

    # ── Per-sample panels ──────────────────────────────────────
    panels = ""
    for i, e in enumerate(entries):
        res      = e.get("result", {})
        raw      = e.get("raw", {})
        scenario = e.get("scenario", f"Sample {i+1}")
        fname    = e.get("file_name", "unknown")
        error    = e.get("error", "")

        cls   = res.get("classification", "ERROR").upper()
        conf  = res.get("confidence", 0)
        risk  = res.get("risk_level", "UNKNOWN").upper()
        score = res.get("severity_score", 0)
        summ  = res.get("summary", "")
        notes = res.get("analyst_notes", "")
        reasoning   = res.get("reasoning", [])
        cve_matches = res.get("cve_matches", [])
        iocs        = res.get("iocs", [])
        next_steps  = res.get("next_steps", [])

        cc = _cls_color(cls)
        rc = _risk_color(risk)

        # gauge arc
        import math
        angle = score * 1.8
        r_arc = 70
        ex = 100 - r_arc * math.cos(math.radians(180 - angle))
        ey = 100 + r_arc * math.sin(math.radians(180 - angle))
        large = 1 if angle > 180 else 0
        gauge_col = "#c0392b" if score >= 60 else ("#e67e22" if score >= 30 else "#27ae60")

        # reasoning rows
        reasoning_html = ""
        for step in reasoning:
            sig = step.get("significance", "LOW").upper()
            reasoning_html += f"""
            <tr>
              <td style="padding:10px 14px;color:#8b949e;width:36px;text-align:center;font-weight:700">{step.get('step','')}</td>
              <td style="padding:10px 14px;color:#c9d1d9;line-height:1.6">{step.get('finding','')}</td>
              <td style="padding:10px 14px;text-align:center">
                <span style="background:{_sig_col(sig)}33;color:{_sig_col(sig)};padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700">{sig}</span>
              </td>
            </tr>"""

        # CVE rows
        cve_html = ""
        for c in cve_matches:
            cid = c.get("cve_id", "")
            cve_html += f"""
            <tr>
              <td style="padding:10px 14px">
                <a href="https://nvd.nist.gov/vuln/detail/{cid}" target="_blank"
                   style="font-family:'IBM Plex Mono',monospace;font-weight:700;color:#e74c3c;text-decoration:none">{cid}</a>
              </td>
              <td style="padding:10px 14px;color:#c9d1d9">{c.get('description','')}</td>
              <td style="padding:10px 14px;color:#8b949e;font-style:italic">{c.get('matched_because','')}</td>
            </tr>"""

        # IOC rows
        ioc_type_colors = {"filename":"#9b59b6","url":"#e74c3c","hash":"#95a5a6","pattern":"#e67e22","string":"#16a085"}
        ioc_html = ""
        for ioc in iocs:
            itype = ioc.get("type","")
            tc = ioc_type_colors.get(itype.lower(), "#7f8c8d")
            ioc_html += f"""
            <tr>
              <td style="padding:10px 14px;text-align:center">
                <span style="background:{tc};color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600">{itype}</span>
              </td>
              <td style="padding:10px 14px;font-family:'IBM Plex Mono',monospace;font-size:12px;color:#c9d1d9;word-break:break-all">{ioc.get('value','')}</td>
              <td style="padding:10px 14px;color:#8b949e">{ioc.get('note','')}</td>
            </tr>"""

        # next steps
        steps_html = "".join(
            f'<li style="padding:8px 0 8px 8px;color:#c9d1d9;line-height:1.6;border-bottom:1px solid #21262d">{s}</li>'
            for s in next_steps
        )

        # file table
        files = raw.get("3_internal_files", [])
        file_rows = ""
        for fi in files[:25]:
            ent = float(fi.get("entropy", 0))
            ec  = "#e74c3c" if ent >= 7.5 else ("#e67e22" if ent >= 6.0 else "#3fb950")
            dbl = " ⚠" if fi.get("has_double_extension") else ""
            hid = " 👁" if fi.get("is_hidden") else ""
            file_rows += f"""
            <tr>
              <td style="padding:7px 12px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:#c9d1d9;word-break:break-all">
                {fi.get('internal_path') or fi.get('file_name','?')}<span style="color:#e67e22">{dbl}{hid}</span>
              </td>
              <td style="padding:7px 12px;color:#8b949e;text-align:right">{fi.get('uncompressed_size',0):,}</td>
              <td style="padding:7px 12px;text-align:center;font-weight:700;color:{ec}">{ent:.2f}</td>
              <td style="padding:7px 12px;color:#8b949e;font-size:11px">{fi.get('detected_mime','')}</td>
            </tr>"""

        # security flags
        sec = raw.get("4_security_indicators", {})
        meta = raw.get("2_archive_metadata", {})
        def flag(label, val):
            v = str(val)
            col = "#e74c3c" if v=="True" else ("#3fb950" if v=="False" else "#c9d1d9")
            icon = "✗" if v=="True" else ("✓" if v=="False" else "")
            return f'<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #21262d"><span style="color:#8b949e;font-size:12px">{label}</span><span style="color:{col};font-weight:600;font-size:12px">{icon} {v}</span></div>'

        error_html = f'<div style="background:#3d1a1a;border:1px solid #c0392b;border-radius:8px;padding:16px;margin-bottom:16px;color:#e74c3c">⚠ LLM Error: {error}</div>' if error else ""

        panels += f"""
        <div class="panel" id="panel-{i}" style="display:none">

          <!-- scenario badge -->
          <div style="margin-bottom:20px">
            <span style="background:#21262d;color:#8b949e;padding:4px 12px;border-radius:20px;font-size:12px">
              {scenario}
            </span>
          </div>

          {error_html}

          <!-- verdict -->
          <div style="background:linear-gradient(135deg,{cc}22,{cc}11);border:1px solid {cc}55;border-radius:12px;padding:24px 28px;display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center;margin-bottom:20px">
            <div>
              <div style="font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#8b949e;margin-bottom:6px">Classification</div>
              <div style="font-size:38px;font-weight:700;color:{cc};font-family:'IBM Plex Mono',monospace;line-height:1">{cls}</div>
              <div style="font-size:13px;color:#8b949e;margin-top:6px">Confidence: <strong style="color:#e6edf3">{conf}%</strong></div>
              <div style="font-size:13px;color:#c9d1d9;line-height:1.7;margin-top:14px;padding-top:14px;border-top:1px solid #30363d">{summ}</div>
            </div>
            <div style="text-align:center">
              <svg width="140" height="90" viewBox="0 0 200 120">
                <path d="M 30 100 A 70 70 0 0 1 170 100" fill="none" stroke="#21262d" stroke-width="14" stroke-linecap="round"/>
                <path d="M 30 100 A 70 70 0 {large} 1 {ex:.1f} {ey:.1f}" fill="none" stroke="{gauge_col}" stroke-width="14" stroke-linecap="round"/>
              </svg>
              <div style="font-size:30px;font-weight:700;color:{gauge_col};font-family:'IBM Plex Mono',monospace;margin-top:-8px">{score}</div>
              <div style="font-size:10px;color:#8b949e;letter-spacing:.05em">SEVERITY / 100</div>
            </div>
          </div>

          <!-- metrics -->
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">
            <div class="metric-card"><div style="font-size:22px;font-weight:700;color:{rc};font-family:'IBM Plex Mono',monospace">{risk}</div><div class="metric-lbl">Risk Level</div></div>
            <div class="metric-card"><div style="font-size:22px;font-weight:700;color:#58a6ff;font-family:'IBM Plex Mono',monospace">{len(cve_matches)}</div><div class="metric-lbl">CVE Matches</div></div>
            <div class="metric-card"><div style="font-size:22px;font-weight:700;color:#f0883e;font-family:'IBM Plex Mono',monospace">{len(iocs)}</div><div class="metric-lbl">IOCs</div></div>
            <div class="metric-card"><div style="font-size:22px;font-weight:700;color:#3fb950;font-family:'IBM Plex Mono',monospace">{len(reasoning)}</div><div class="metric-lbl">Findings</div></div>
          </div>

          <!-- archive info + flags -->
          <div class="section-card">
            <div class="section-hdr">📦 Archive Metadata</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;padding:20px">
              <div>
                <div style="font-size:11px;color:#8b949e;font-weight:700;margin-bottom:10px;text-transform:uppercase">Basic Info</div>
                <div style="font-size:12px;font-family:'IBM Plex Mono',monospace;color:#c9d1d9;word-break:break-all;margin-bottom:8px">{fname}</div>
                <div style="font-size:12px;color:#8b949e">Format: <span style="color:#c9d1d9">{meta.get('format','?')}</span> &nbsp;|&nbsp; Ratio: <span style="color:#c9d1d9">{meta.get('compression_ratio',0)}x</span></div>
                <div style="font-size:12px;color:#8b949e;margin-top:4px">Files: <span style="color:#c9d1d9">{meta.get('file_count', len(files))}</span> &nbsp;|&nbsp; Size: <span style="color:#c9d1d9">{raw.get('1_basic_info',{}).get('file_size',0):,} B</span></div>
              </div>
              <div>
                <div style="font-size:11px;color:#8b949e;font-weight:700;margin-bottom:10px;text-transform:uppercase">Security Flags</div>
                {flag("Encrypted", meta.get("password_protected", False))}
                {flag("Corrupted", meta.get("corrupted", False))}
                {flag("Has executables", sec.get("has_executables", False))}
                {flag("Has LNK shortcuts", sec.get("has_lnk", False))}
                {flag("Has macros", sec.get("has_office_macros", False))}
                {flag("Archive bomb", sec.get("archive_bomb_suspected", False))}
                {flag("RTLO detected", sec.get("unicode_rtlo_detected", False))}
                {flag("Decoy + exec", sec.get("decoy_and_executable_combo", False))}
              </div>
            </div>
          </div>

          <!-- reasoning -->
          <div class="section-card">
            <div class="section-hdr">🔍 Step-by-Step Findings</div>
            <table style="width:100%;border-collapse:collapse">
              <thead><tr>
                <th style="padding:10px 14px;text-align:left;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d;width:40px">#</th>
                <th style="padding:10px 14px;text-align:left;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d">Finding</th>
                <th style="padding:10px 14px;text-align:center;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d;width:110px">Significance</th>
              </tr></thead>
              <tbody>{reasoning_html or '<tr><td colspan="3" style="padding:16px;text-align:center;color:#484f58">No findings.</td></tr>'}</tbody>
            </table>
          </div>

          <!-- CVEs -->
          <div class="section-card">
            <div class="section-hdr">🛡️ CVE Matches (2000–2025)</div>
            <table style="width:100%;border-collapse:collapse">
              <thead><tr>
                <th style="padding:10px 14px;text-align:left;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d;width:155px">CVE ID</th>
                <th style="padding:10px 14px;text-align:left;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d">Description</th>
                <th style="padding:10px 14px;text-align:left;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d">Matched Because</th>
              </tr></thead>
              <tbody>{cve_html or '<tr><td colspan="3" style="padding:16px;text-align:center;color:#484f58">No CVE matches.</td></tr>'}</tbody>
            </table>
          </div>

          <!-- IOCs -->
          <div class="section-card">
            <div class="section-hdr">⚠️ Indicators of Compromise</div>
            <table style="width:100%;border-collapse:collapse">
              <thead><tr>
                <th style="padding:10px 14px;text-align:center;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d;width:110px">Type</th>
                <th style="padding:10px 14px;text-align:left;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d">Value</th>
                <th style="padding:10px 14px;text-align:left;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d">Note</th>
              </tr></thead>
              <tbody>{ioc_html or '<tr><td colspan="3" style="padding:16px;text-align:center;color:#484f58">No IOCs.</td></tr>'}</tbody>
            </table>
          </div>

          <!-- file listing -->
          <div class="section-card">
            <div class="section-hdr">📁 Internal Files</div>
            <table style="width:100%;border-collapse:collapse">
              <thead><tr>
                <th style="padding:8px 12px;text-align:left;font-size:11px;font-weight:700;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d">Path / Filename</th>
                <th style="padding:8px 12px;text-align:right;font-size:11px;font-weight:700;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d;width:100px">Size (B)</th>
                <th style="padding:8px 12px;text-align:center;font-size:11px;font-weight:700;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d;width:80px">Entropy</th>
                <th style="padding:8px 12px;text-align:left;font-size:11px;font-weight:700;color:#8b949e;background:#0d1117;border-bottom:1px solid #30363d;width:180px">MIME</th>
              </tr></thead>
              <tbody>{file_rows or '<tr><td colspan="4" style="padding:16px;text-align:center;color:#484f58">No file listing.</td></tr>'}</tbody>
            </table>
          </div>

          <!-- analyst notes -->
          <div class="section-card">
            <div class="section-hdr">📝 Analyst Notes</div>
            <div style="padding:20px;font-size:13px;line-height:1.8;color:#c9d1d9;white-space:pre-wrap;border-left:3px solid {cc};margin:16px;border-radius:0 8px 8px 0;background:#0d1117">{notes or "—"}</div>
          </div>

          <!-- next steps -->
          <div class="section-card">
            <div class="section-hdr">✅ Recommended Next Steps</div>
            <ol style="list-style:none;counter-reset:steps;padding:16px 20px">
              {steps_html or '<li style="color:#484f58;padding:8px 0">No recommendations.</li>'}
            </ol>
          </div>

        </div>"""

    # ── Overview table rows ────────────────────────────────────
    overview_rows = ""
    for i, e in enumerate(entries):
        res   = e.get("result", {})
        cls   = res.get("classification", "ERROR").upper()
        score = res.get("severity_score", 0)
        risk  = res.get("risk_level", "?").upper()
        conf  = res.get("confidence", 0)
        cc    = _cls_color(cls)
        rc    = _risk_color(risk)
        fname = e.get("file_name", "unknown")
        cve_count = len(res.get("cve_matches", []))
        ioc_count = len(res.get("iocs", []))
        err   = "⚠" if e.get("error") else ""
        overview_rows += f"""
        <tr onclick="showPanel({i})" style="cursor:pointer">
          <td style="padding:10px 14px;color:#8b949e;width:36px;text-align:center">{i+1}</td>
          <td style="padding:10px 14px;font-family:'IBM Plex Mono',monospace;font-size:12px;color:#c9d1d9">{fname} {err}</td>
          <td style="padding:10px 14px;text-align:center">
            <span style="background:{cc}33;color:{cc};padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700">{cls}</span>
          </td>
          <td style="padding:10px 14px;text-align:center">
            <span style="background:{rc}33;color:{rc};padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700">{risk}</span>
          </td>
          <td style="padding:10px 14px;text-align:center;font-family:'IBM Plex Mono',monospace;color:{cc};font-weight:700">{score}</td>
          <td style="padding:10px 14px;text-align:center;color:#8b949e">{conf}%</td>
          <td style="padding:10px 14px;text-align:center;color:#58a6ff">{cve_count}</td>
          <td style="padding:10px 14px;text-align:center;color:#f0883e">{ioc_count}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SEC530 — Archive Suite Analysis Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

  *, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0; }}
  html, body {{ height:100%; }}

  body {{
    font-family:'IBM Plex Sans',sans-serif;
    background:#0d1117;
    color:#e6edf3;
    display:flex;
    flex-direction:column;
    min-height:100vh;
  }}

  /* ── Top bar ── */
  .topbar {{
    background:#161b22;
    border-bottom:1px solid #30363d;
    padding:0 24px;
    display:flex;
    align-items:center;
    gap:16px;
    height:56px;
    flex-shrink:0;
    position:sticky;
    top:0;
    z-index:100;
  }}
  .topbar-title {{ font-size:15px; font-weight:700; color:#e6edf3; }}
  .topbar-sub   {{ font-size:12px; color:#8b949e; font-family:'IBM Plex Mono',monospace; }}
  .topbar-meta  {{ margin-left:auto; font-size:11px; color:#484f58; }}

  .stat-pill {{
    display:flex; align-items:center; gap:6px;
    background:#21262d; border-radius:20px;
    padding:4px 12px; font-size:12px; font-weight:600;
  }}

  /* ── Layout ── */
  .layout {{
    display:flex;
    flex:1;
    overflow:hidden;
  }}

  /* ── Sidebar ── */
  .sidebar {{
    width:260px;
    flex-shrink:0;
    background:#161b22;
    border-right:1px solid #30363d;
    overflow-y:auto;
    display:flex;
    flex-direction:column;
  }}
  .sidebar-section {{
    padding:12px 16px 6px;
    font-size:10px;
    font-weight:700;
    letter-spacing:.08em;
    text-transform:uppercase;
    color:#484f58;
  }}
  .sidebar-item {{
    display:flex;
    align-items:center;
    gap:10px;
    padding:10px 16px;
    cursor:pointer;
    border-bottom:1px solid #21262d;
    transition:background .15s;
  }}
  .sidebar-item:hover {{ background:#1c2128; }}
  .sidebar-item.active {{ background:#1c2128; border-left:3px solid #58a6ff; padding-left:13px; }}
  .si-icon  {{ font-size:16px; flex-shrink:0; }}
  .si-body  {{ flex:1; min-width:0; }}
  .si-name  {{ font-size:12px; font-family:'IBM Plex Mono',monospace; color:#c9d1d9; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .si-label {{ font-size:10px; color:#8b949e; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-top:2px; }}
  .si-score {{ font-size:13px; font-weight:700; font-family:'IBM Plex Mono',monospace; flex-shrink:0; }}

  /* ── Main content ── */
  .main {{
    flex:1;
    overflow-y:auto;
    padding:28px 32px 60px;
  }}

  /* ── Overview panel ── */
  #overview-panel table {{ width:100%; border-collapse:collapse; }}
  #overview-panel th {{
    padding:10px 14px; text-align:left;
    font-size:11px; font-weight:700; letter-spacing:.05em;
    text-transform:uppercase; color:#8b949e;
    background:#0d1117; border-bottom:1px solid #30363d;
  }}
  #overview-panel td {{ border-bottom:1px solid #21262d; }}
  #overview-panel tr:hover td {{ background:#1c2128; }}

  /* ── Shared card styles ── */
  .section-card {{
    background:#161b22;
    border:1px solid #30363d;
    border-radius:10px;
    margin-bottom:16px;
    overflow:hidden;
  }}
  .section-hdr {{
    padding:13px 18px;
    border-bottom:1px solid #30363d;
    font-size:12px;
    font-weight:700;
    letter-spacing:.05em;
    text-transform:uppercase;
    color:#8b949e;
  }}
  .metric-card {{
    background:#161b22;
    border:1px solid #30363d;
    border-radius:10px;
    padding:16px;
    text-align:center;
  }}
  .metric-lbl {{
    font-size:10px; color:#8b949e;
    margin-top:5px; letter-spacing:.05em; text-transform:uppercase;
  }}

  /* ── summary stat cards ── */
  .summary-grid {{
    display:grid;
    grid-template-columns:repeat(5,1fr);
    gap:12px;
    margin-bottom:24px;
  }}
  .sum-card {{
    background:#161b22;
    border:1px solid #30363d;
    border-radius:10px;
    padding:16px;
    text-align:center;
  }}
  .sum-val {{ font-size:28px; font-weight:700; font-family:'IBM Plex Mono',monospace; }}
  .sum-lbl {{ font-size:10px; color:#8b949e; margin-top:4px; letter-spacing:.05em; text-transform:uppercase; }}

  tr td {{ transition:background .1s; }}
</style>
</head>
<body>

<!-- ═══ TOP BAR ══════════════════════════════════════════════ -->
<div class="topbar">
  <div>🗂</div>
  <div>
    <div class="topbar-title">Archive Suite Analysis Report</div>
    <div class="topbar-sub">SEC530 · Task 3 · LLM-Based Analysis</div>
  </div>
  <div class="stat-pill" style="color:#e74c3c">🔴 {mal} Malicious</div>
  <div class="stat-pill" style="color:#e67e22">🟡 {sus} Suspicious</div>
  <div class="stat-pill" style="color:#2ecc71">🟢 {ben} Benign</div>
  {'<div class="stat-pill" style="color:#e74c3c">⚠ ' + str(errors) + ' Errors</div>' if errors else ''}
  <div class="topbar-meta">{model} · {now}</div>
</div>

<!-- ═══ LAYOUT ════════════════════════════════════════════════ -->
<div class="layout">

  <!-- sidebar -->
  <div class="sidebar">
    <div class="sidebar-section">Overview</div>
    <div class="sidebar-item active" id="nav-overview" onclick="showOverview()">
      <div class="si-icon">📊</div>
      <div class="si-body">
        <div class="si-name">All Samples</div>
        <div class="si-label">{total} samples analyzed</div>
      </div>
    </div>
    <div class="sidebar-section" style="margin-top:8px">Samples</div>
    {sidebar_items}
  </div>

  <!-- main -->
  <div class="main">

    <!-- ── overview panel ── -->
    <div id="overview-panel">
      <div class="summary-grid">
        <div class="sum-card"><div class="sum-val" style="color:#58a6ff">{total}</div><div class="sum-lbl">Total</div></div>
        <div class="sum-card"><div class="sum-val" style="color:#e74c3c">{mal}</div><div class="sum-lbl">Malicious</div></div>
        <div class="sum-card"><div class="sum-val" style="color:#e67e22">{sus}</div><div class="sum-lbl">Suspicious</div></div>
        <div class="sum-card"><div class="sum-val" style="color:#2ecc71">{ben}</div><div class="sum-lbl">Benign</div></div>
        <div class="sum-card"><div class="sum-val" style="color:#8b949e">{errors}</div><div class="sum-lbl">Errors</div></div>
      </div>

      <div class="section-card">
        <div class="section-hdr">📋 All Samples — Click a row to view details</div>
        <table>
          <thead><tr>
            <th>#</th><th>File Name</th><th style="text-align:center">Classification</th>
            <th style="text-align:center">Risk</th><th style="text-align:center">Score</th>
            <th style="text-align:center">Confidence</th><th style="text-align:center">CVEs</th>
            <th style="text-align:center">IOCs</th>
          </tr></thead>
          <tbody>{overview_rows}</tbody>
        </table>
      </div>
    </div>

    <!-- ── per-sample panels ── -->
    {panels}

  </div><!-- /main -->
</div><!-- /layout -->

<script>
  function showOverview() {{
    document.querySelectorAll('.panel').forEach(p => p.style.display = 'none');
    document.getElementById('overview-panel').style.display = 'block';
    document.querySelectorAll('.sidebar-item').forEach(n => n.classList.remove('active'));
    document.getElementById('nav-overview').classList.add('active');
  }}

  function showPanel(i) {{
    document.querySelectorAll('.panel').forEach(p => p.style.display = 'none');
    document.getElementById('overview-panel').style.display = 'none';
    document.getElementById('panel-' + i).style.display = 'block';
    document.querySelectorAll('.sidebar-item').forEach(n => n.classList.remove('active'));
    var navItem = document.getElementById('nav-' + i);
    if (navItem) {{
      navItem.classList.add('active');
      navItem.scrollIntoView({{block:'nearest'}});
    }}
  }}
</script>
</body>
</html>"""

    return html


def run_suite(
    suite_path: str,
    client: LLMClient,
    provider: str,
    model: str,
    output_path: str,
    delay: float = 2.0,
) -> None:
    print(f"[*] Loading suite : {suite_path}")
    with open(suite_path, "r", encoding="utf-8") as fh:
        suite = json.load(fh)

    samples = suite.get("test_samples", [])
    if not samples:
        print("[!] No 'test_samples' found in suite JSON.")
        return

    print(f"[*] Samples       : {len(samples)}")
    print(f"[*] Provider      : {provider} / {model}")
    print(f"[*] Output        : {output_path}\n")

    entries: list[dict] = []

    for i, raw_sample in enumerate(samples, 1):
        # Strip _ meta keys
        raw   = {k: v for k, v in raw_sample.items() if not k.startswith("_")}
        scenario = raw_sample.get("_scenario", f"Sample {i}")
        fname    = raw.get("1_basic_info", {}).get("file_name", f"sample_{i}")

        print(f"[{i:02d}/{len(samples)}] {scenario}")
        print(f"         File: {fname}")

        entry: dict = {"scenario": scenario, "file_name": fname, "raw": raw}

        try:
            prompt = build_user_prompt(raw)
            t0     = time.time()
            result = client.analyze(prompt)
            elapsed = time.time() - t0

            cls   = result.get("classification", "?")
            score = result.get("severity_score", 0)
            print(f"         → {cls}  score={score}/100  "
                  f"CVEs={len(result.get('cve_matches',[]))}  "
                  f"IOCs={len(result.get('iocs',[]))}  ({elapsed:.1f}s)")

            entry["result"] = result
            entry["error"]  = ""

        except Exception as exc:
            print(f"         [ERROR] {exc}", file=sys.stderr)
            entry["result"] = {
                "classification": "ERROR", "confidence": 0,
                "risk_level": "UNKNOWN", "severity_score": 0,
                "summary": str(exc), "reasoning": [], "cve_matches": [],
                "iocs": [], "next_steps": [], "analyst_notes": str(exc),
            }
            entry["error"] = str(exc)

        entries.append(entry)

        # Rate-limit pause (skip after last)
        if i < len(samples):
            time.sleep(delay)

    print(f"\n[*] Generating HTML report...")
    html = generate_suite_html(entries, provider, model)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    mal = sum(1 for e in entries if e.get("result",{}).get("classification","").upper() == "MALICIOUS")
    sus = sum(1 for e in entries if e.get("result",{}).get("classification","").upper() == "SUSPICIOUS")
    ben = sum(1 for e in entries if e.get("result",{}).get("classification","").upper() == "BENIGN")
    err = sum(1 for e in entries if e.get("error"))

    print(f"\n{'='*55}")
    print(f"  SUITE COMPLETE")
    print(f"{'='*55}")
    print(f"  Total    : {len(entries)}")
    print(f"  Malicious: {mal}  Suspicious: {sus}  Benign: {ben}  Errors: {err}")
    print(f"  Report   : {output_path}")
    print(f"{'='*55}\n")


# ──────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SEC530 Task 3 — LLM-Based Archive Analyzer"
    )
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("json_file", nargs="?", help="Single Task 1 JSON file")
    grp.add_argument("--batch", metavar="DIR", help="Directory of Task 1 JSON files")
    grp.add_argument("--suite", metavar="FILE", help="Test suite JSON (contains test_samples list)")

    parser.add_argument(
        "--provider", default="claude",
        choices=list(PROVIDERS),
        help="LLM provider (default: claude). gemini = Google AI Studio key",
    )
    parser.add_argument(
        "--api-key", default="",
        help="API key (not needed for ollama)",
    )
    parser.add_argument(
        "--model", default=None,
        help="Model name override (default: provider's default model)",
    )
    parser.add_argument(
        "--max-tokens", type=int, default=2048,
        help="Max tokens for LLM response (default: 2048)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output HTML file",
    )
    parser.add_argument(
        "--output-dir", default="llm_reports",
        help="Output directory for batch mode (default: llm_reports/)",
    )
    parser.add_argument(
        "--delay", type=float, default=2.0,
        help="Seconds between API calls in suite/batch mode (default: 2.0)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    client = LLMClient(
        provider=args.provider,
        api_key=args.api_key,
        model=args.model,
        max_tokens=args.max_tokens,
    )
    model_name = args.model or PROVIDERS[args.provider]["model"]

    if args.suite:
        default_out = Path(args.suite).stem + "_llm_report.html"
        output = args.output or default_out
        run_suite(args.suite, client, args.provider, model_name, output, delay=args.delay)
    elif args.batch:
        run_batch(args.batch, client, args.provider, model_name, args.output_dir)
    else:
        default_out = Path(args.json_file).stem + "_llm_report.html"
        output = args.output or default_out
        run_single(args.json_file, client, args.provider, model_name, output)


if __name__ == "__main__":
    main()