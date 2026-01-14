from sast.orchestrator import run_security_checks

input_data = {
    "run_id": "test-run-1",
    "repo_path": ".",
    "languages": ["python"],
}

result = run_security_checks(input_data)

print("Findings:", len(result["findings"]))
for f in result["findings"]:
    print(f)

