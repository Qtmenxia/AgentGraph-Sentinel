"""
Graph-based repair suggestion (competition feature):
Compute minimal interventions to block UNTRUSTED -> high-privilege sinks.
Outputs suggested edges to cut + where to insert gate/sanitizer nodes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import networkx as nx


@dataclass
class RepairSuggestion:
    kind: str  # "insert_gate" | "insert_sanitizer" | "block_tool"
    edge: Tuple[str, str]
    score: float
    reason: str


class GraphRepairAdvisor:
    def __init__(self):
        # lower cost => prefer intervening here
        self.edge_cost = {
            "data_flow": 1.0,
            "control_flow": 2.0,
            "edge": 2.0,
        }

    def suggest(self, G: nx.DiGraph, sources: List[str], sinks: List[str], topk: int = 5) -> Dict[str, Any]:
        """
        Uses min-cut on a converted flow graph:
          - add super source connected to sources
          - add super sink connected from sinks
          - edge capacities = cost
        Returns top interventions (cut edges) + recommended actions.
        """
        if not sources or not sinks or G.number_of_edges() == 0:
            return {"suggestions": [], "summary": {"reason": "no_sources_or_sinks_or_edges"}}

        H = nx.DiGraph()
        for u, v, d in G.edges(data=True):
            et = str(d.get("type", "edge"))
            cap = float(self.edge_cost.get(et, 2.5))
            H.add_edge(u, v, capacity=cap)

        super_s = "__super_source__"
        super_t = "__super_sink__"
        for s in sources:
            if s in G:
                H.add_edge(super_s, s, capacity=0.5)
        for t in sinks:
            if t in G:
                H.add_edge(t, super_t, capacity=0.5)

        try:
            cut_value, (S, T) = nx.minimum_cut(H, super_s, super_t, capacity="capacity")
        except Exception:
            return {"suggestions": [], "summary": {"reason": "min_cut_failed"}}

        cut_edges = []
        for u in S:
            for v in H.successors(u):
                if v in T:
                    if u == super_s or v == super_t:
                        continue
                    cut_edges.append((u, v, H[u][v].get("capacity", 1.0)))

        # convert to suggestions
        suggestions: List[RepairSuggestion] = []
        for u, v, cap in sorted(cut_edges, key=lambda x: x[2])[:topk]:
            et = str(G.get_edge_data(u, v, {}).get("type", "edge"))
            kind = "insert_sanitizer" if et == "data_flow" else "insert_gate"
            reason = "cut on untrusted-to-sink paths"
            suggestions.append(RepairSuggestion(kind=kind, edge=(u, v), score=float(1.0 / (cap + 1e-6)), reason=reason))

        return {
            "suggestions": [s.__dict__ for s in suggestions],
            "summary": {"cut_value": float(cut_value), "n_cut_edges": len(cut_edges), "sources": sources, "sinks": sinks},
        }
