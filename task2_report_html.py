"""
SEC530 - Project 3: Task 2
HTML Report Generator

Usage:
    # From a combined/suite report JSON:
    python task2_report_html.py combined_report.json --output report.html

    # From a single-file Task 2 JSON:
    python task2_report_html.py single_report.json --output report.html

    # Directly from a Task 1 feature file:
    python task2_report_html.py feature.json --from-task1 --output report.html

    # Directly from a test suite (Task 1 format):
    python task2_report_html.py test_suite.json --from-suite --output report.html
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime


# --------------------------------------------------
#  SCORE COLOR
# --------------------------------------------------

def score_color(score: int) -> str:
    if score >= 80:   return "#E24B4A"
    elif score >= 50: return "#EF9F27"
    elif score >= 20: return "#378ADD"
    return "#639922"


def classification_icon(c: str) -> str:
    return {"MALICIOUS": "⚠", "SUSPICIOUS": "◈", "BENIGN": "✓"}.get(c, "?")


# --------------------------------------------------
#  RULE ROW
# --------------------------------------------------

def rule_row_html(rule: dict) -> str:
    sev   = rule.get("severity", "LOW")
    cve   = rule.get("cve") or ""
    colors = {
        "CRITICAL": ("#FCEBEB", "#A32D2D"),
        "HIGH":     ("#FAEEDA", "#854F0B"),
        "MEDIUM":   ("#E6F1FB", "#185FA5"),
        "LOW":      ("#EAF3DE", "#3B6D11"),
    }
    bg, fg = colors.get(sev, ("#F1EFE8", "#5f5e5a"))
    cve_badge = (f'<span style="background:#F1EFE8;color:#5f5e5a;font-family:monospace;'
                 f'font-size:11px;padding:2px 7px;border-radius:5px;margin-left:4px;">'
                 f'{cve}</span>') if cve else ""
    return f"""
<div style="border-bottom:0.5px solid rgba(0,0,0,0.07);padding:9px 0;">
  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:3px;">
    <span style="font-family:monospace;font-size:12px;color:#888780;">{rule.get("rule_id","?")}</span>
    <span style="background:{bg};color:{fg};font-size:11px;padding:2px 8px;border-radius:6px;font-weight:500;">{sev}</span>
    {cve_badge}
    <span style="font-size:13px;color:#1c1c1a;">{rule.get("description","")}</span>
  </div>
  <p style="font-size:11px;font-family:monospace;color:#888780;padding-left:4px;word-break:break-word;">{rule.get("evidence","")}</p>
</div>"""


# --------------------------------------------------
#  SINGLE SAMPLE SECTION
# --------------------------------------------------

def sample_section_html(r: dict, idx: int) -> str:
    clf   = r.get("classification", "BENIGN")
    score = r.get("severity_score", 0)
    rules = r.get("triggered_rules", [])
    hashes = r.get("hashes", {})
    scenario = r.get("scenario", r.get("file_name", f"Sample {idx}"))

    clf_colors = {
        "MALICIOUS":  ("#FCEBEB", "#A32D2D"),
        "SUSPICIOUS": ("#FAEEDA", "#854F0B"),
        "BENIGN":     ("#EAF3DE", "#3B6D11"),
    }
    clf_bg, clf_fg = clf_colors.get(clf, ("#F1EFE8", "#5f5e5a"))

    bar_color = score_color(score)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_rules = sorted(rules, key=lambda x: sev_order.get(x.get("severity", "LOW"), 4))
    rules_html = "".join(rule_row_html(r) for r in sorted_rules) if sorted_rules else \
        '<p style="font-size:13px;color:#888780;">No rules triggered.</p>'

    cves = [r["cve"] for r in rules if r.get("cve")]
    cve_html = ""
    if cves:
        badges = " ".join(f'<span style="background:#F1EFE8;color:#5f5e5a;font-family:monospace;font-size:11px;padding:2px 7px;border-radius:5px;">{c}</span>' for c in cves)
        cve_html = f'<div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap;align-items:center;"><span style="font-size:12px;color:#888780;">matched CVEs:</span>{badges}</div>'

    hash_rows = ""
    for key in ("md5", "sha1", "sha256"):
        val = hashes.get(key, "—")
        hash_rows += f'<div style="color:#888780;font-size:12px;">{key}</div><div style="font-family:monospace;font-size:11px;word-break:break-all;">{val}</div>'

    explanation = r.get("explanation", "").replace("<", "&lt;").replace(">", "&gt;")

    return f"""
<div id="sample-{idx}" style="border:0.5px solid rgba(0,0,0,0.1);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;background:#fff;">

  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:1.25rem;">
    <div>
      <p style="font-size:12px;color:#888780;margin-bottom:3px;">#{idx} &nbsp;·&nbsp; {scenario}</p>
      <h2 style="font-size:17px;font-weight:500;color:#1c1c1a;">{r.get("file_name","unknown")}</h2>
    </div>
    <span style="background:{clf_bg};color:{clf_fg};padding:5px 14px;border-radius:8px;font-size:13px;font-weight:500;white-space:nowrap;">
      {classification_icon(clf)} {clf}
    </span>
  </div>

  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:1.25rem;">
    <div style="background:#f5f5f4;border-radius:8px;padding:0.85rem;">
      <p style="font-size:11px;color:#888780;margin-bottom:3px;">severity score</p>
      <p style="font-size:20px;font-weight:500;">{score}/100</p>
      <div style="background:#e5e5e3;border-radius:99px;height:6px;margin-top:5px;overflow:hidden;">
        <div style="width:{score}%;height:6px;border-radius:99px;background:{bar_color};"></div>
      </div>
    </div>
    <div style="background:#f5f5f4;border-radius:8px;padding:0.85rem;">
      <p style="font-size:11px;color:#888780;margin-bottom:3px;">risk level</p>
      <p style="font-size:20px;font-weight:500;">{r.get("risk_level","LOW")}</p>
    </div>
    <div style="background:#f5f5f4;border-radius:8px;padding:0.85rem;">
      <p style="font-size:11px;color:#888780;margin-bottom:3px;">rules triggered</p>
      <p style="font-size:20px;font-weight:500;">{len(rules)}</p>
    </div>
    <div style="background:#f5f5f4;border-radius:8px;padding:0.85rem;">
      <p style="font-size:11px;color:#888780;margin-bottom:3px;">CVE matches</p>
      <p style="font-size:20px;font-weight:500;">{len(cves)}</p>
    </div>
  </div>

  {"" if not hashes else f'''
  <div style="background:#f5f5f4;border-radius:8px;padding:0.85rem;margin-bottom:1rem;display:grid;grid-template-columns:auto 1fr;gap:4px 16px;">
    {hash_rows}
  </div>'''}

  <div style="margin-bottom:1rem;">
    <p style="font-size:12px;font-weight:500;color:#888780;margin-bottom:8px;">triggered rules ({len(rules)})</p>
    {rules_html}
  </div>

  <div style="border-top:0.5px solid rgba(0,0,0,0.07);padding-top:0.85rem;">
    <p style="font-size:12px;font-weight:500;color:#888780;margin-bottom:6px;">explanation</p>
    <p style="font-size:13px;line-height:1.75;color:#444441;white-space:pre-wrap;">{explanation}</p>
    {cve_html}
  </div>

</div>"""


# --------------------------------------------------
#  FULL HTML PAGE
# --------------------------------------------------

def generate_html(data: dict) -> str:
    # data can be either a single result or a combined {"summary":..., "results":[...]}
    if "results" in data:
        results  = data["results"]
        summary  = data.get("summary", {})
    else:
        results  = [data]
        summary  = {data.get("classification", "BENIGN"): 1}

    total     = len(results)
    malicious = summary.get("MALICIOUS", 0)
    suspicious = summary.get("SUSPICIOUS", 0)
    benign    = summary.get("BENIGN", 0)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # TOC
    toc_items = ""
    for i, r in enumerate(results, 1):
        clf = r.get("classification", "BENIGN")
        clf_colors = {"MALICIOUS": "#A32D2D", "SUSPICIOUS": "#854F0B", "BENIGN": "#3B6D11"}
        col = clf_colors.get(clf, "#888780")
        toc_items += f'<a href="#sample-{i}" style="display:flex;align-items:center;gap:8px;padding:6px 0;text-decoration:none;border-bottom:0.5px solid rgba(0,0,0,0.06);">' \
                     f'<span style="font-size:11px;color:#888780;min-width:24px;">#{i}</span>' \
                     f'<span style="font-size:13px;color:#1c1c1a;flex:1;">{r.get("file_name","?")}</span>' \
                     f'<span style="font-size:11px;font-weight:500;color:{col};">{clf}</span></a>'

    samples_html = "".join(sample_section_html(r, i) for i, r in enumerate(results, 1))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Task 2 — Archive Analysis Report</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:system-ui,-apple-system,sans-serif; background:#f5f5f4; color:#1c1c1a; }}
  a {{ color:inherit; }}
  @media print {{ body {{ background:#fff; }} }}
</style>
</head>
<body>
<div style="max-width:860px;margin:0 auto;padding:2rem 1rem;">

  <div style="margin-bottom:2rem;">
    <p style="font-size:12px;color:#888780;margin-bottom:6px;">sec530 · project 3 · task 2 · static rule-based detection · {timestamp}</p>
    <h1 style="font-size:24px;font-weight:500;margin-bottom:1.25rem;">archive analysis report</h1>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:1.5rem;">
      <div style="background:#fff;border:0.5px solid rgba(0,0,0,0.1);border-radius:10px;padding:1rem;">
        <p style="font-size:11px;color:#888780;margin-bottom:3px;">total analyzed</p>
        <p style="font-size:26px;font-weight:500;">{total}</p>
      </div>
      <div style="background:#FCEBEB;border-radius:10px;padding:1rem;">
        <p style="font-size:11px;color:#A32D2D;margin-bottom:3px;">malicious</p>
        <p style="font-size:26px;font-weight:500;color:#A32D2D;">{malicious}</p>
      </div>
      <div style="background:#FAEEDA;border-radius:10px;padding:1rem;">
        <p style="font-size:11px;color:#854F0B;margin-bottom:3px;">suspicious</p>
        <p style="font-size:26px;font-weight:500;color:#854F0B;">{suspicious}</p>
      </div>
      <div style="background:#EAF3DE;border-radius:10px;padding:1rem;">
        <p style="font-size:11px;color:#3B6D11;margin-bottom:3px;">benign</p>
        <p style="font-size:26px;font-weight:500;color:#3B6D11;">{benign}</p>
      </div>
    </div>

    <div style="background:#fff;border:0.5px solid rgba(0,0,0,0.1);border-radius:10px;padding:1rem;margin-bottom:1.5rem;">
      <p style="font-size:12px;font-weight:500;color:#888780;margin-bottom:8px;">contents</p>
      {toc_items}
    </div>
  </div>

  {samples_html}

  <p style="font-size:11px;color:#b4b2a9;text-align:center;margin-top:2rem;">
    generated by sec530 task 2 detector &middot; {timestamp}
  </p>

</div>
</body>
</html>"""


# --------------------------------------------------
#  CLI
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Task 2 HTML Report Generator")
    parser.add_argument("input", help="Combined report JSON or single Task 2 JSON")
    parser.add_argument("--output", default="report.html", help="Output HTML file")
    parser.add_argument("--from-task1", action="store_true",
                        help="Input is a single Task 1 feature JSON")
    parser.add_argument("--from-suite", action="store_true",
                        help="Input is a test suite JSON (contains test_samples list)")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    if args.from_task1 or args.from_suite:
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from task2_detector import analyze, normalize_features, report_to_dict
        except ImportError:
            print("[!] task2_detector.py not found — must be in the same directory.")
            sys.exit(1)

        if args.from_suite:
            samples = data.get("test_samples", [])
            results = []
            summary = {"BENIGN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
            for i, raw in enumerate(samples, 1):
                clean    = {k: v for k, v in raw.items() if not k.startswith("_")}
                scenario = raw.get("_scenario", f"Sample {i}")
                features   = normalize_features(clean)
                report_obj = analyze(clean)
                result     = report_to_dict(report_obj, features)
                result["scenario"] = scenario
                results.append(result)
                summary[result["classification"]] = summary.get(result["classification"], 0) + 1
            data = {"summary": summary, "results": results}
        else:
            features   = normalize_features(data)
            report_obj = analyze(data)
            data = report_to_dict(report_obj, features)

    html = generate_html(data)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML report generated -> {args.output}")


if __name__ == "__main__":
    main()
