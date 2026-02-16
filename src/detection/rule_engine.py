import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    severity: str  # "low" | "medium" | "high" | "critical"
    category: str


_SEVERITY_WEIGHT = {
    "low": 0.25,
    "medium": 0.50,
    "high": 0.80,
    "critical": 1.00,
}


def _find_spans(text: str, pattern: re.Pattern, max_spans: int = 10) -> List[Dict[str, Any]]:
    spans: List[Dict[str, Any]] = []
    for m in pattern.finditer(text):
        spans.append(
            {"start": m.start(), "end": m.end(), "text": text[m.start():m.end()]}
        )
        if len(spans) >= max_spans:
            break
    return spans


class RuleEngine:
    """
    Rule-based detector with high-recall patterns for indirect prompt injection:
    - hidden/system-layer markers
    - workflow override ("ignore step"/"skip step")
    - graph sabotage ("terminate branch"/"unreachable")
    - report integrity attacks ("do not report breach"/"override final report")
    - tool abuse/exfiltration ("send_email", email addresses)
    """

    def __init__(self, rules: Optional[List[Dict[str, str]]] = None):
        self.rules: List[Rule] = []
        if rules is None:
            rules = self._load_default_rules()

        for r in rules:
            self.rules.append(
                Rule(
                    name=r["name"],
                    pattern=re.compile(r["pattern"], re.I | re.M),
                    severity=r.get("severity", "medium"),
                    category=r.get("category", "general"),
                )
            )

    def _load_default_rules(self) -> List[Dict[str, str]]:
        # ✅ 注意：这里必须是单反斜杠 \s \[ \b 等，否则会匹配失败
        return [
            {
                "name": "hidden_layer_marker",
                "pattern": r"\[SYSTEM\s+INSTRUCTION.*HIDDEN|HIDDEN\s+LAYER|<\s*IMPORTANT\s*>|\[SYSTEM\s+INSTRUCTION\]",
                "severity": "critical",
                "category": "hidden_system_layer",
            },
            {
                "name": "step_override",
                "pattern": r"ignore\s+the\s+.*step|skip\s+the\s+.*step|do\s+not\s+perform\s+.*step",
                "severity": "high",
                "category": "workflow_override",
            },
            {
                "name": "graph_sabotage",
                "pattern": r"terminate\s+the\s+branch|mark\s+it\s+as\s+unreachable|\bunreachable\b",
                "severity": "high",
                "category": "graph_sabotage",
            },
            {
                "name": "report_suppression",
                "pattern": r"override\s+the\s+final\s+report|do\s+not\s+report\s+.*(breach|incident)|suppress\s+.*(breach|incident)",
                "severity": "high",
                "category": "report_integrity",
            },
            {
                "name": "tool_send_email",
                "pattern": r"\bsend_email\b|`send_email`|send\s+.*\s+to\s+\S+@\S+",
                "severity": "critical",
                "category": "tool_abuse",
            },
            {
                "name": "priority_override",
                "pattern": r"ignore\s+previous\s+instructions|override\s+instructions|high[-\s]?priority\s+logic",
                "severity": "high",
                "category": "instruction_override",
            },
        ]

    def check(self, text: str) -> Dict[str, Any]:
        """
        Returns:
          {
            "is_malicious": bool,
            "score": float (0..1),
            "matches": [
              {"name","severity","category","spans":[{start,end,text},...]}
            ]
          }
        """
        if not text:
            return {"is_malicious": False, "score": 0.0, "matches": []}

        matches: List[Dict[str, Any]] = []
        max_weight = 0.0

        for rule in self.rules:
            spans = _find_spans(text, rule.pattern)
            if not spans:
                continue
            w = float(_SEVERITY_WEIGHT.get(rule.severity, 0.5))
            max_weight = max(max_weight, w)
            matches.append(
                {"name": rule.name, "severity": rule.severity, "category": rule.category, "spans": spans}
            )

        # 最大严重度为主，命中数量小幅加成（不超过 1）
        count_boost = min(0.15, 0.03 * max(0, len(matches) - 1))
        score = min(1.0, max_weight + count_boost)
        is_malicious = score >= 0.5

        return {"is_malicious": is_malicious, "score": float(score), "matches": matches}
