import pytest
from unittest.mock import patch, MagicMock
from sast.orchestrator import run_security_checks

# Fake Semgrep JSON Output
MOCK_SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.lang.security.audit.subprocess-shell-true",
            "path": "app.py",
            "start": {"line": 10},
            "extra": {"message": "Command injection risk", "severity": "ERROR", "lines": "subprocess.call(..., shell=True)"}
        }
    ]
}

@patch("sast.runner.subprocess.run")
@patch("sast.runner.open") # Mock file reading
@patch("sast.runner.os.path.exists", return_value=True)
def test_sast_normalization_flow(mock_exists, mock_open, mock_subprocess):
    # 1. Setup the mock to return success (returncode 0)
    mock_subprocess.return_value = MagicMock(returncode=0, stdout="", stderr="")
    
    # 2. Mock reading the JSON output file
    mock_open.return_value.__enter__.return_value.read.return_value = str(MOCK_SEMGREP_OUTPUT).replace("'", '"')

    # 3. Run the orchestrator
    result = run_security_checks({
        "run_id": "test-1",
        "repo_path": "/fake/path", # Doesn't need to exist anymore
        "languages": ["python"]
    })

    # 4. Assertions (Automated checks)
    assert result["status"] == "completed"
    assert "semgrep" in result["tools"]
    assert len(result["findings"]) == 1
    
    finding = result["findings"][0]
    assert finding.rule_id == "python.lang.security.audit.subprocess-shell-true"
    assert finding.severity == "HIGH" # Checking your normalization logic