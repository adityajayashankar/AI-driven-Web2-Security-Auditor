import subprocess
import tempfile
import json
import os
from typing import Dict, Any, List, Optional

def run_nuclei(target_url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Run Nuclei active scan.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = tmp.name

    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        # [FIX] Critical tags for web vulnerabilities
        "-severity", "low,medium,high,critical",
        "-tags", "cves,misconfig,exposed-panels,auth,xss,sqli,vuln",
        
        # [FIX] Your setting: 100s is decent for single-page scans
        "-timeout", "300", 
        "-rate-limit", "150",
        
        "-disable-update-check",
        "-o", output_path,
    ]

    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    print(f"🚀 Running Nuclei DAST on {target_url}...")
    
    try:
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )
    except subprocess.CalledProcessError:
        pass

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
            if os.path.exists(output_path):
                os.remove(output_path)
        except OSError:
            pass

    return {
        "target": target_url,
        "results": results,
    }