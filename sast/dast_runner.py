import subprocess
import tempfile
import json
import os
from typing import Dict, Any, List, Optional

def run_nuclei(target_url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Run Nuclei active scan.
    """
    # Create a temporary file to store JSON output
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = tmp.name

    # Build the Nuclei command
    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        # Critical tags for web vulnerabilities
        "-severity", "low,medium,high,critical",
        "-tags", "cves,misconfig,exposed-panels,auth,xss,sqli,vuln",
        
        # Tuning for performance vs stability
        "-timeout", "300", 
        "-rate-limit", "150",
        
        "-disable-update-check",
        "-o", output_path,
    ]

    # Add custom headers if provided (e.g. for authentication)
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    print(f"🚀 Running Nuclei DAST on {target_url}...")
    
    # [FIX] Use check=False to prevent crashing on non-zero exit codes.
    # Nuclei returns 1 if vulnerabilities are found or if targets are missing,
    # which we want to handle gracefully, not crash.
    proc = subprocess.run(
        cmd,
        check=False,  # <--- CRITICAL FIX: Do not raise exception on exit code 1
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True
    )

    # Optional: Log warnings if it didn't exit cleanly (exit code 0)
    if proc.returncode != 0:
        print(f"⚠️ Nuclei exited with code {proc.returncode}")
        # Print the first 200 characters of stderr to help debug connectivity issues
        if proc.stderr:
            print(f"   Stderr: {proc.stderr[:200]}...") 

    results: List[dict] = []
    try:
        # Parse the JSON output file
        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    finally:
        # Cleanup: Ensure the temp file is removed even if parsing fails
        try:
            if os.path.exists(output_path):
                os.remove(output_path)
        except OSError:
            pass

    return {
        "target": target_url,
        "results": results,
    }