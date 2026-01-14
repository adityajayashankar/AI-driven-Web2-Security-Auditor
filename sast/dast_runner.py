import subprocess
import tempfile
import json
from typing import Dict, Any, List


def run_nuclei(target_url: str) -> Dict[str, Any]:
    """
    Run Nuclei in SAFE, deterministic mode against a single target URL.
    Produces structured JSON output suitable for normalization.

    This function:
    - does NOT parse findings
    - does NOT apply intelligence
    - only executes the tool
    """

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = tmp.name

    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-severity", "low,medium,high,critical",
        "-tags", "cves,misconfig,exposed-panels,auth",
        "-rate-limit", "150",
        "-timeout", "5",
        "-retries", "1",
        "-o", output_path,
    ]

    subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    results: List[dict] = []
    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            results.append(json.loads(line))

    return {
        "target": target_url,
        "results": results,
    }
