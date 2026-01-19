import subprocess
import tempfile
import json
import os
from typing import Dict, Any, List, Optional


def run_nuclei(
    target_url: str,
    headers: Optional[Dict[str, str]] = None,
    profile: str = "ci",  # ci | deep
) -> Dict[str, Any]:
    """
    Run Nuclei DAST scan (safe by default).
    """

    with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
        output_path = tmp.name

    # ---- SAFE DEFAULT FLAGS (CI / PROD) ----
    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-o", output_path,

        # 🚦 SEVERITY (no low in CI)
        "-severity", "medium,high,critical",

        # 🎯 REAL WEB ISSUES ONLY
        "-tags", "xss,sqli,auth,misconfig,exposure",

        # ⚡ PERFORMANCE CONTROLS
        "-timeout", "10",
        "-retries", "1",
        "-rl", "100",        # rate limit
        "-c", "50",          # concurrency
        "-max-host-error", "30",

        "-disable-update-check",
        "-silent",
    ]

    # ---- OPTIONAL DEEP SCAN (explicit only) ----
    if profile == "deep":
        cmd.extend([
            "-tags", "xss,sqli,auth,misconfig,exposure,cves",
            "-timeout", "20",
            "-rl", "200",
        ])

    # ---- AUTH HEADERS ----
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

    print(f"🚀 Running Nuclei ({profile}) on {target_url}...")

    proc = subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    if proc.returncode > 1:
        print("⚠️ Nuclei execution issue:")
        print(proc.stderr[:500])

    results: List[dict] = []

    try:
        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    finally:
        try:
            os.remove(output_path)
        except OSError:
            pass

    return {
        "tool": "nuclei",
        "target": target_url,
        "profile": profile,
        "results": results,
        "count": len(results),
    }
