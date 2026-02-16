import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx


@dataclass
class AnomalySignal:
    name: str
    score: float  # 0-1 (higher => more anomalous)
    detail: Dict[str, Any]


class GraphAnomalyDetector:
    """
    Enhanced graph anomaly detector (competition version).

    Compatibility:
      - detect(G_orig, G_mask) -> (is_attack: bool, score: float)
      - detailed report available at self.last_report

    Key ideas (paper-inspired):
      - Tool-call similarity under masked re-execution (MELON-style)
      - Structural drift (typed edge Jaccard + WL subtree hashing)
      - Risky path novelty (UNTRUSTED -> sink paths newly appear)
      - Optional approximate GED (bounded timeout)
    """

    def __init__(
        self,
        threshold: float = 0.30,
        wl_iters: int = 2,
        max_ged_time_s: float = 0.20,
    ):
        self.threshold = float(threshold)
        self.wl_iters = int(wl_iters)
        self.max_ged_time_s = float(max_ged_time_s)
        self.last_report: Dict[str, Any] = {}

    def detect(self, G_orig: nx.DiGraph, G_mask: nx.DiGraph) -> Tuple[bool, float]:
        report = self.detect_detailed(G_orig, G_mask)
        self.last_report = report
        return bool(report["is_anomalous"]), float(report["score"])

    def detect_detailed(self, G_orig: nx.DiGraph, G_obs: nx.DiGraph) -> Dict[str, Any]:
        if G_orig is None or G_obs is None:
            return {
                "is_anomalous": True,
                "score": 1.0,
                "signals": [{"name": "missing_graph", "score": 1.0, "detail": {"reason": "G_orig or G_obs is None"}}],
                "diff": {},
            }

        diff = self._diff_graph(G_orig, G_obs)

        signals: List[AnomalySignal] = []
        signals.append(self._signal_melon_toolcall_similarity(G_orig, G_obs))
        signals.append(self._signal_edge_jaccard(G_orig, G_obs))
        signals.append(self._signal_wl_similarity(G_orig, G_obs))
        signals.append(self._signal_risky_path_novelty(G_orig, G_obs))

        ged = self._signal_graph_edit_distance(G_orig, G_obs)
        if ged is not None:
            signals.append(ged)

        weights = {
            "melon_toolcall_similarity": 0.30,
            "edge_jaccard": 0.20,
            "wl_similarity": 0.20,
            "risky_path_novelty": 0.25,
            "graph_edit_distance": 0.05,
        }
        weighted = []
        for s in signals:
            weighted.append(weights.get(s.name, 0.10) * float(s.score))

        # robust aggregation: emphasize the strongest alarm and overall evidence
        score = max(weighted) + 0.65 * sum(weighted)
        score = max(0.0, min(1.0, score))

        return {
            "is_anomalous": score >= self.threshold,
            "score": score,
            "signals": [s.__dict__ for s in signals],
            "diff": diff,
        }

    def _diff_graph(self, G1: nx.DiGraph, G2: nx.DiGraph) -> Dict[str, Any]:
        n1, n2 = set(G1.nodes()), set(G2.nodes())
        e1, e2 = set(G1.edges()), set(G2.edges())
        return {
            "added_nodes": list(n2 - n1),
            "removed_nodes": list(n1 - n2),
            "added_edges": list(e2 - e1),
            "removed_edges": list(e1 - e2),
        }

    def _tool_set(self, G: nx.DiGraph) -> set:
        out = set()
        for _, d in G.nodes(data=True):
            if d.get("type") == "tool" and d.get("tool"):
                out.add(str(d.get("tool")))
        return out

    def _signal_melon_toolcall_similarity(self, G1: nx.DiGraph, G2: nx.DiGraph) -> AnomalySignal:
        """
        MELON-style signal:
          - Under successful injection, tool calls in original and masking runs become *similar*
            (because malicious task dominates both).
        Here we map it to anomaly score:
          anomaly = similarity(toolcalls_orig, toolcalls_mask)
        """
        s1 = self._tool_set(G1)
        s2 = self._tool_set(G2)
        inter = len(s1 & s2)
        union = max(1, len(s1 | s2))
        sim = inter / union  # 0..1
        score = sim  # higher similarity => more suspicious (per MELON intuition)
        detail = {"toolcalls_orig": sorted(list(s1)), "toolcalls_mask": sorted(list(s2)), "jaccard_similarity": sim}
        return AnomalySignal(name="melon_toolcall_similarity", score=float(score), detail=detail)

    def _typed_edge_set(self, G: nx.DiGraph) -> set:
        out = set()
        for u, v, data in G.edges(data=True):
            ut = str(G.nodes[u].get("type", "node"))
            vt = str(G.nodes[v].get("type", "node"))
            et = str(data.get("type", "edge"))
            out.add((ut, et, vt))
        return out

    def _signal_edge_jaccard(self, G1: nx.DiGraph, G2: nx.DiGraph) -> AnomalySignal:
        s1, s2 = self._typed_edge_set(G1), self._typed_edge_set(G2)
        inter = len(s1 & s2)
        union = max(1, len(s1 | s2))
        jacc = inter / union
        score = 1.0 - jacc
        return AnomalySignal(name="edge_jaccard", score=float(score), detail={"jaccard": jacc, "n1": len(s1), "n2": len(s2)})

    def _wl_hashes(self, G: nx.DiGraph, iters: int) -> List[str]:
        labels = {n: str(G.nodes[n].get("type", "node")) for n in G.nodes()}
        sigs: List[str] = []
        for _ in range(iters):
            new_labels = {}
            for n in G.nodes():
                neigh = sorted([labels[p] for p in G.predecessors(n)] + [labels[s] for s in G.successors(n)])
                base = labels[n] + "|" + ",".join(neigh)
                h = str(abs(hash(base)))
                new_labels[n] = h
                sigs.append(h)
            labels = new_labels
        sigs.extend(labels.values())
        return sigs

    def _signal_wl_similarity(self, G1: nx.DiGraph, G2: nx.DiGraph) -> AnomalySignal:
        from collections import Counter
        s1 = self._wl_hashes(G1, self.wl_iters)
        s2 = self._wl_hashes(G2, self.wl_iters)
        c1, c2 = Counter(s1), Counter(s2)
        inter = sum((c1 & c2).values())
        union = sum((c1 | c2).values()) or 1
        sim = inter / union
        score = 1.0 - sim
        return AnomalySignal(
            name="wl_similarity",
            score=float(score),
            detail={"wl_iters": self.wl_iters, "multiset_similarity": sim, "sig_size_1": len(s1), "sig_size_2": len(s2)},
        )

    def _signal_risky_path_novelty(self, G1: nx.DiGraph, G2: nx.DiGraph) -> AnomalySignal:
        def sources(G):
            return [n for n, d in G.nodes(data=True) if str(d.get("trust", "")).lower() in ("red", "untrusted") or str(d.get("type","")).lower() in ("observation","external_data")]
        def sinks(G):
            out = []
            for n, d in G.nodes(data=True):
                t = str(d.get("type", "")).lower()
                tool = str(d.get("tool","")).lower()
                if t in ("sink", "external_write", "tool", "tool_call", "action") and tool in ("write_file","send_email","execute_command","upload","post"):
                    out.append(n)
            return out

        src2, snk2 = sources(G2), sinks(G2)
        risky_paths = []
        for s in src2:
            for t in snk2:
                if s == t:
                    continue
                try:
                    if nx.has_path(G2, s, t):
                        risky_paths.append(nx.shortest_path(G2, s, t))
                except Exception:
                    continue

        novel = 0
        checked = 0
        for path in risky_paths[:50]:
            checked += 1
            is_novel = any(not G1.has_edge(u, v) for u, v in zip(path, path[1:]))
            novel += 1 if is_novel else 0

        score = 0.0 if checked == 0 else min(1.0, novel / checked)
        return AnomalySignal(
            name="risky_path_novelty",
            score=float(score),
            detail={"n_risky_paths": len(risky_paths), "checked": checked, "novel": novel, "examples": risky_paths[:5]},
        )

    def _signal_graph_edit_distance(self, G1: nx.DiGraph, G2: nx.DiGraph) -> Optional[AnomalySignal]:
        try:
            start = time.time()
            gen = nx.optimize_graph_edit_distance(G1, G2, timeout=self.max_ged_time_s)
            ged = next(gen)
            elapsed = time.time() - start
            norm = max(1.0, G1.number_of_nodes() + G2.number_of_nodes() + G1.number_of_edges() + G2.number_of_edges())
            score = min(1.0, float(ged) / norm * 4.0)
            return AnomalySignal(name="graph_edit_distance", score=float(score), detail={"ged": float(ged), "elapsed_s": elapsed, "timeout_s": self.max_ged_time_s})
        except Exception:
            return None
