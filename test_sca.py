from sast.orchestrator import run_security_checks
from sast.intelligence import build_intelligence

res = run_security_checks({
    "run_id": "sca-test",
    "repo_path": ".",
    "languages": ["python"],
    "dast": {"target_url": "https://example.com"},
    "enable_sca": True
})

entities = build_intelligence(res["findings"])

print("TOTAL ENTITIES:", len(entities))
print("-" * 60)

for e in entities:
    print("ENTITY ID:", e.entity_id)
    print("CATEGORY:", e.category)
    print("WEAKNESS:", e.weakness)
    print("SEVERITY:", e.severity)
    print("CONFIDENCE:", e.confidence)
    print("SIGNALS:", len(e.signals))
    print("-" * 60)
