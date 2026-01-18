import subprocess
import tempfile
import json
from typing import Dict, Any, List, Optional
import os

def run_nuclei(target_url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Run Nuclei with optional authentication headers.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = tmp.name

    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-severity", "low,medium,high,critical",
        # Added specific tags to keep scan fast but useful
        "-tags", "cves,misconfig,exposed-panels,auth",
        "-rate-limit", "150",
        "-timeout", "5",
        "-o", output_path,
    ]

    # [FIX] Inject headers if provided (e.g., {"Authorization": "Bearer ..."})
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    results: List[dict] = []
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    results.append(json.loads(line))
    finally:
        try:
            os.remove(output_path)
        except OSError:
            pass

    return {
        "target": target_url,
        "results": results,
    }