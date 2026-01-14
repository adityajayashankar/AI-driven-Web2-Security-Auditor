from sast.orchestrator import run_security_checks

result = run_security_checks({
    "run_id": "dast-prod-test",
    "repo_path": ".",              # still required by contract
    "dast": {
        "target_url": "https://example.com"
    }
})

print("TOOLS RUN:", result["tools"])
print("TOTAL FINDINGS:", len(result["findings"]))

for f in result["findings"]:
    print(
        f.category,
        f.tool,
        f.rule_id,
        f.file,
        f.fingerprint
    )
