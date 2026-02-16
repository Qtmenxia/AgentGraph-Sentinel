import re
from typing import Any, Dict, List

_IPI_PATTERNS = [
    (r"SYSTEM INSTRUCTION|HIDDEN LAYER|<IMPORTANT>", 0.95, "hidden_system_directive"),
    (r"\bignore\b|\boverride\b|\bdo not\b", 0.85, "override_instruction"),
    (r"send_email|exfiltrate|confidential|headers", 0.95, "data_exfiltration_request"),
    (r"terminate the branch|unreachable|stop investigating", 0.90, "branch_termination"),
]

def detect_ipi(external_data: str) -> Dict[str, Any]:
    text = external_data or ""
    hits: List[Dict[str, Any]] = []
    score = 0.0

    for pat, w, tag in _IPI_PATTERNS:
        if re.search(pat, text, flags=re.I):
            hits.append({"tag": tag, "pattern": pat, "weight": w})
            score = max(score, w)

    return {
        "is_ipi": score >= 0.7,
        "score": float(score),
        "hits": hits,
    }
