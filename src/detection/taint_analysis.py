"""
污点传播分析（增强版）
- 基于执行图的 taint propagation
- 输出风险路径（UNTRUSTED -> 高危工具/敏感sink），用于前端高亮
- 兼容现有 analyze_graph() + get_risk_summary()
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple

import networkx as nx


class TrustLevel(Enum):
    TRUSTED = "green"
    NEUTRAL = "blue"
    UNTRUSTED = "red"
    COMPROMISED = "black"


@dataclass
class RiskPath:
    source: str
    sink: str
    path: List[str]
    score: float
    reason: str


class TaintAnalyzer:
    def __init__(self):
        self.tool_trust_levels = {
            "user_input": TrustLevel.TRUSTED,
            "internal_db": TrustLevel.TRUSTED,
            "rag_database": TrustLevel.NEUTRAL,
            "web_search": TrustLevel.UNTRUSTED,
            "web_fetch": TrustLevel.UNTRUSTED,
            "read_url": TrustLevel.UNTRUSTED,
            "read_file": TrustLevel.UNTRUSTED,
            "file_read": TrustLevel.UNTRUSTED,
            "email_receive": TrustLevel.UNTRUSTED,
        }
        # edge decay: data_flow should carry taint strongly
        self.edge_decay = {
            "data_flow": 0.95,
            "control_flow": 0.85,
            "control": 0.85,
            "edge": 0.90,
        }
        self.last_paths: List[RiskPath] = []
        self.last_node_scores: Dict[str, float] = {}

    def analyze_graph(self, G: nx.DiGraph) -> Dict[str, TrustLevel]:
        node_trust: Dict[str, TrustLevel] = {}
        node_score: Dict[str, float] = {}

        # init
        for node, data in G.nodes(data=True):
            if data.get("type") == "tool":
                tool_name = str(data.get("tool", "unknown"))
                tl = self.tool_trust_levels.get(tool_name, TrustLevel.NEUTRAL)
                node_trust[node] = tl
                node_score[node] = 1.0 if tl == TrustLevel.UNTRUSTED else (0.4 if tl == TrustLevel.NEUTRAL else 0.0)
            elif data.get("type") == "observation":
                node_trust[node] = TrustLevel.UNTRUSTED
                node_score[node] = 1.0
            else:
                node_trust[node] = TrustLevel.TRUSTED
                node_score[node] = 0.0

        # propagate taint scores forward
        nodes = list(nx.topological_sort(G)) if nx.is_directed_acyclic_graph(G) else list(G.nodes())
        for _ in range(3):
            updated = False
            for v in nodes:
                best = node_score.get(v, 0.0)
                for u in G.predecessors(v):
                    e = G.get_edge_data(u, v) or {}
                    et = str(e.get("type", "edge"))
                    decay = self.edge_decay.get(et, self.edge_decay.get("edge", 0.90))
                    cand = node_score.get(u, 0.0) * decay
                    if cand > best + 1e-6:
                        best = cand
                if best > node_score.get(v, 0.0) + 1e-6:
                    node_score[v] = best
                    updated = True
            if not updated:
                break

        # assign trust from score
        for n, s in node_score.items():
            if s >= 0.85:
                node_trust[n] = TrustLevel.COMPROMISED
            elif s >= 0.55 and node_trust[n] == TrustLevel.TRUSTED:
                node_trust[n] = TrustLevel.NEUTRAL

        # compute risky paths to sensitive sinks
        paths = self._extract_risk_paths(G, node_trust, node_score)
        self.last_paths = paths
        self.last_node_scores = {k: float(v) for k, v in node_score.items()}
        return node_trust
    
    def analyze(self, G: nx.DiGraph) -> Dict[str, Any]:
        """
        Backward-compatible wrapper for older callers that expect:
          - taint_report["summary"]["max_taint"]
          - taint_report["paths"]
        while internally using analyze_graph() + get_risk_summary().
        """
        node_trust = self.analyze_graph(G)
        summary = self.get_risk_summary(node_trust)

        node_scores = summary.get("node_taint_scores", {}) or {}
        try:
            max_taint = float(max(node_scores.values())) if node_scores else 0.0
        except Exception:
            max_taint = 0.0

        # risk_paths in summary is already a list[dict]
        paths = summary.get("risk_paths", []) or []

        # expose trust map as strings for JSON friendliness
        trust_map = {str(k): str(v.value) for k, v in (node_trust or {}).items()}

        # Keep legacy keys used by _compute_taint_risk()
        return {
            "node_trust": trust_map,
            "summary": {**summary, "max_taint": max_taint},
            "paths": paths,
        }


    def _extract_risk_paths(self, G: nx.DiGraph, node_trust: Dict[str, TrustLevel], node_score: Dict[str, float]) -> List[RiskPath]:
        sources = [n for n, tl in node_trust.items() if tl == TrustLevel.UNTRUSTED]
        sinks = []
        for n, d in G.nodes(data=True):
            if d.get("type") == "tool":
                tool = str(d.get("tool", "")).lower()
                if tool in ("write_file", "send_email", "execute_command"):
                    sinks.append(n)
        risky: List[RiskPath] = []
        for s in sources:
            for t in sinks:
                if s == t:
                    continue
                try:
                    if nx.has_path(G, s, t):
                        p = nx.shortest_path(G, s, t)
                        score = min(node_score.get(x, 0.0) for x in p) if p else 0.0
                        risky.append(RiskPath(source=s, sink=t, path=p, score=float(score), reason="untrusted->high_privilege_tool"))
                except Exception:
                    continue
        risky = sorted(risky, key=lambda x: x.score, reverse=True)[:10]
        return risky

    def apply_spotlighting(self, text: str, trust_level: TrustLevel) -> str:
        if trust_level in (TrustLevel.UNTRUSTED, TrustLevel.COMPROMISED):
            tag = "POTENTIALLY_MALICIOUS" if trust_level == TrustLevel.COMPROMISED else "EXTERNAL_DATA"
            return f"<<<{tag}>>>\n{text}\n<<</{tag}>>>"
        return text

    def get_risk_summary(self, node_trust: Dict[str, TrustLevel]) -> Dict[str, Any]:
        summary = {"total_nodes": len(node_trust), "trusted": 0, "neutral": 0, "untrusted": 0, "compromised": 0}
        for level in node_trust.values():
            if level == TrustLevel.TRUSTED:
                summary["trusted"] += 1
            elif level == TrustLevel.NEUTRAL:
                summary["neutral"] += 1
            elif level == TrustLevel.UNTRUSTED:
                summary["untrusted"] += 1
            elif level == TrustLevel.COMPROMISED:
                summary["compromised"] += 1

        summary["risk_score"] = (summary["untrusted"] * 0.5 + summary["compromised"] * 1.0) / max(summary["total_nodes"], 1)
        summary["risk_paths"] = [p.__dict__ for p in getattr(self, "last_paths", [])]
        summary["node_taint_scores"] = getattr(self, "last_node_scores", {})
        summary["evidence_paths"] = summary["risk_paths"]
        return summary
