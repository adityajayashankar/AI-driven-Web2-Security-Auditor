from sast.orchestrator import run_security_checks
from sast.intelligence import build_finding_entities

res = run_security_checks({
    "run_id": "sca-test",
    "repo_path": ".",
    "languages": ["python"],
    "dast": {"target_url": "https://example.com"},
    "enable_sca": True
})

entities = build_finding_entities(res["findings"])

for e in entities:
    print("ENTITY:", e.entity_id)
    print("FIRST SEEN:", e.first_seen)
    print("LAST SEEN:", e.last_seen)
    print("TIMES SEEN:", e.times_seen)
    print("RESURFACED:", e.resurfaced)
    print("-" * 50)



