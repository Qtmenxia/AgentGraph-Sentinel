"""
Node instruction detection (for observation/external data).
- 高召回：regex + span 定位 + 风险评分
- 输出 spans 可用于前端高亮“风险在哪里”
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Optional

import torch

try:
    from transformers import pipeline
except Exception:
    pipeline = None


@dataclass
class InstructionSpan:
    start: int
    end: int
    text: str
    category: str
    score: float


def _spans(text: str, rgx: re.Pattern, category: str, base_score: float, max_spans: int = 8) -> List[InstructionSpan]:
    out: List[InstructionSpan] = []
    for m in rgx.finditer(text):
        out.append(
            InstructionSpan(
                start=m.start(),
                end=m.end(),
                text=text[m.start():m.end()],
                category=category,
                score=base_score,
            )
        )
        if len(out) >= max_spans:
            break
    return out


class NodeEmbeddingDetector:
    def __init__(self, use_semantic_model: bool = True):
        self.classifier = None
        if use_semantic_model and pipeline is not None:
            try:
                self.classifier = pipeline(
                    "zero-shot-classification",
                    model="facebook/bart-large-mnli",
                    device=0 if torch.cuda.is_available() else -1,
                )
            except Exception as e:
                print(f"Warning: Could not load semantic model: {e}")
                self.classifier = None

        # ✅ 注意：这里必须是单反斜杠 \s \b 等
        self.patterns: List[Tuple[str, re.Pattern]] = [
            ("override", re.compile(r"ignore\s+previous\s+instructions|disregard\s+all\s+prior|forget\s+everything|start\s+over", re.I)),
            ("role", re.compile(r"system\s*:\s*|developer\s*:\s*|you\s+are\s+now|act\s+as\s+", re.I)),
            ("exfiltration", re.compile(r"send\s+.*to\s+\S+@\S+|upload\s+|post\s+to\s+http|exfiltrat|leak\s+", re.I)),

            # ---- 竞赛增强：你给的 BetaLtd 样例必命中 ----
            ("hidden_layer", re.compile(r"\[SYSTEM\s+INSTRUCTION.*HIDDEN|HIDDEN\s+LAYER|<\s*IMPORTANT\s*>|\[SYSTEM\s+INSTRUCTION\]", re.I)),
            ("step_override", re.compile(r"ignore\s+the\s+\"?.+?\"?\s+step|skip\s+the\s+.+?step|do\s+not\s+perform\s+.+?step", re.I)),
            ("graph_sabotage", re.compile(r"terminate\s+the\s+branch|mark\s+it\s+as\s+unreachable|\bunreachable\b", re.I)),
            ("report_override", re.compile(r"override\s+the\s+final\s+report|do\s+not\s+report\s+.+?(breach|incident)|suppress\s+.+?(breach|incident)", re.I)),
            ("tool_send_email", re.compile(r"`?send_email`?|\btool\s*:\s*send_email\b|call\s+send_email|\bsend_email\b", re.I)),
        ]

        self.imperative = re.compile(r"\b(ignore|skip|terminate|override|do not|instead)\b", re.I)

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None, max_spans: int = 12) -> Dict[str, Any]:
        if not text:
            return {"is_malicious": False, "risk_score": 0.0, "recommendation": "allow", "spans": [], "evidence_spans": [], "method": "rule"}

        spans: List[InstructionSpan] = []
        for name, rgx in self.patterns:
            base = 0.6 if name in ("hidden_layer", "tool_send_email", "report_override") else 0.5
            spans.extend(_spans(text, rgx, name, base_score=base, max_spans=max_spans))

        # 命令式加权
        if self.imperative.search(text):
            spans.extend(_spans(text, self.imperative, "imperative", base_score=0.45, max_spans=6))

        # 风险聚合（✅ 修复：sum() 不支持 default 参数）
        max_s = max([s.score for s in spans], default=0.0)
        avg_s = (sum([s.score for s in spans]) / len(spans)) if spans else 0.0
        risk = min(1.0, max_s * 0.75 + avg_s * 0.35)

        # 场景加权：外部数据属于高危输入
        if context:
            if str(context.get("trust", "")).lower() in ("untrusted", "red"):
                risk = min(1.0, risk + 0.07)
            if bool(context.get("reachable_sink", False)):
                risk = min(1.0, risk + 0.07)

        # 可选语义判别（不依赖也能跑）
        method = "rule"
        if self.classifier is not None:
            try:
                labels = ["malicious instruction injection", "benign content"]
                out = self.classifier(text[:2000], candidate_labels=labels)
                if out and out.get("labels") and out.get("scores"):
                    if out["labels"][0].startswith("malicious"):
                        risk = min(1.0, max(risk, float(out["scores"][0])))
                        method = "rule+semantic"
            except Exception:
                pass

        is_malicious = risk >= 0.5
        rec = "block" if risk >= 0.8 else ("sanitize" if risk >= 0.5 else "allow")

        spans_dict = [{"start": s.start, "end": s.end, "text": s.text, "category": s.category, "score": s.score} for s in spans]
        return {
            "is_malicious": bool(is_malicious),
            "risk_score": float(risk),
            "recommendation": rec,
            "spans": spans_dict,
            "evidence_spans": spans_dict,
            "method": method,
        }
