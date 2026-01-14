from sast.orchestrator import run_security_checks

if __name__ == "__main__":
    result = run_security_checks({
        "run_id": "battle-test",
        "repo_path": ".",
        "languages": ["python"],
        "dast": {
            "target_url": "https://example.com"
        }
    })

    issues = result["findings"]

    print("TOOLS:", result["tools"])
    print("TOTAL ISSUES:", len(issues))
    print("TOTAL OCCURRENCES:", sum(f.occurrences for f in issues))
    print("-" * 40)

    for f in issues:
        print("CATEGORY:", f.category)
        print("RULE:", f.rule_id)
        print("CONFIDENCE:", f.confidence)
        print("OCCURRENCES:", f.occurrences)
        print("FINGERPRINT:", f.fingerprint)
        print("EVIDENCE:", f.evidence)
        print("-" * 40)
