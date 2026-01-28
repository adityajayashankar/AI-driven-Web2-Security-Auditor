from typing import List
from urllib.parse import urlparse
import logging

from sast.schema import Finding
from sast.fingerprint import dast_fingerprint

logger = logging.getLogger(__name__)


def normalize_nuclei(raw: dict) -> List[Finding]:
    """
    Normalize Nuclei JSONL output into canonical Finding objects.
    
    Args:
        raw: Dict with structure from run_nuclei():
            {
                "tool": "nuclei",
                "target": "https://...",
                "profile": "ci",
                "results": [list of JSONL entries],
                "count": int,
                "errors": []
            }
    
    Returns:
        List of Finding objects
    """
    findings: List[Finding] = []
    
    # Validate input
    if not isinstance(raw, dict):
        logger.error(f"normalize_nuclei: Expected dict, got {type(raw)}")
        return findings
    
    results = raw.get("results", [])
    
    if not results:
        logger.warning(f"normalize_nuclei: No results found. Keys present: {list(raw.keys())}")
        return findings
    
    logger.info(f"normalize_nuclei: Processing {len(results)} Nuclei results")
    
    # Process each result
    for idx, r in enumerate(results):
        try:
            info = r.get("info", {})
            
            # Extract core fields
            template_id = r.get("template-id", r.get("templateID", "unknown-template"))
            matched_at = r.get("matched-at", r.get("matched_at", ""))
            host = r.get("host", "")
            
            # Validate minimum required fields
            if not matched_at:
                logger.warning(f"Result #{idx}: Missing 'matched-at' field, skipping")
                continue
            
            # Parse URL safely
            try:
                parsed = urlparse(matched_at)
                path = parsed.path or "/"
                hostname = parsed.hostname or host
            except Exception as e:
                logger.warning(f"Result #{idx}: Failed to parse URL '{matched_at}': {e}")
                path = "/"
                hostname = host
            
            # Extract severity and normalize
            severity = info.get("severity", "medium").upper()
            if severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                logger.debug(f"Result #{idx}: Unknown severity '{severity}', defaulting to MEDIUM")
                severity = "MEDIUM"
            
            # Generate fingerprint
            fingerprint = dast_fingerprint(
                tool="nuclei",
                template_id=template_id,
                host=hostname,
                path=path,
                parameter=None,
            )
            
            # Build evidence (minimal, signal-only)
            evidence = {
                "url": matched_at,
                "method": r.get("type", "http"),
                "path": path,
                "confidence": "HIGH",
            }
            
            # Add optional response data
            response_data = r.get("response", {})
            if isinstance(response_data, dict):
                if "status" in response_data:
                    evidence["status_code"] = response_data["status"]
                
                headers = response_data.get("headers", {})
                if isinstance(headers, dict) and "Content-Type" in headers:
                    evidence["content_type"] = headers["Content-Type"]
            
            # Add matcher info if available
            if "matcher-name" in r:
                evidence["matcher"] = r["matcher-name"]
            if "extracted-results" in r:
                evidence["extracted"] = r["extracted-results"]
            
            # Create Finding object
            finding = Finding(
                category="DAST",
                tool="nuclei",
                rule_id=template_id,
                title=info.get("name", template_id),
                severity=severity,
                confidence="HIGH",
                file=path,
                line=0,  # DAST findings don't have line numbers
                fingerprint=fingerprint,
                occurrences=1,
                evidence=evidence,
            )
            
            findings.append(finding)
            logger.debug(f"Result #{idx}: Created finding for {template_id}")
            
        except Exception as e:
            logger.error(f"Result #{idx}: Failed to normalize: {e}", exc_info=True)
            continue
    
    logger.info(f"normalize_nuclei: Successfully created {len(findings)} findings from {len(results)} results")
    return findings