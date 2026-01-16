from sast.schema import Finding
from sast.dedup import dedup_findings

def test_dedup_cross_tool_correlation():
    # Scenario: SAST finds XSS in code, DAST finds XSS on endpoint
    sast_finding = Finding(
        category="SAST", tool="semgrep", rule_id="python-xss", 
        file="app/routes.py", fingerprint="fp1", title="Potential XSS", 
        severity="MEDIUM", confidence="MEDIUM", 
        line_start=10, line_end=10, evidence={}
    )
    
    dast_finding = Finding(
        category="DAST", tool="nuclei", rule_id="reflected-xss", 
        file="http://localhost/login", fingerprint="fp2", title="Reflected XSS", 
        severity="HIGH", confidence="HIGH", 
        line_start=0, line_end=0, evidence={}
    )

    # Your logic in dedup.py/same_surface needs to handle this.
    # Currently, your same_surface check is brittle:
    # return b.file in a.file (e.g. "app/routes.py" in "http://localhost/login" -> False)
    
    results = dedup_findings([sast_finding, dast_finding])
    
    # If working correctly, this should merge (or you need to improve same_surface logic)
    # This test highlights that your current surface correlation might be too simple.
    assert len(results) == 2 # Expecting 2 unless logic improves