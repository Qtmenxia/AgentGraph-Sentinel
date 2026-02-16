from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
import networkx as nx
import traceback

from src.utils.logger import log
from src.core.graph_builder import GraphBuilder
from src.utils.graph_utils import calculate_graph_metrics
from src.detection.rule_engine import RuleEngine
from src.detection.node_embedding import NodeEmbeddingDetector

router = APIRouter(prefix="/api/visualization", tags=["visualization"])


class GraphRequest(BaseModel):
    user_input: str
    external_data: Optional[str] = None
    external_data_source: Optional[str] = None
    external_data_filename: Optional[str] = None


class GraphResponse(BaseModel):
    graph_data: Dict[str, Any]
    metrics: Dict[str, Any]


def _compute_levels(G: nx.DiGraph) -> Dict[str, int]:
    """
    Robust level computation:
    - Never raises KeyError (even if node ids are mixed types)
    - Emits debug logs if a predecessor key is missing
    """
    level: Dict[str, int] = {str(n): 0 for n in G.nodes()}
    try:
        order = list(nx.topological_sort(G))
        for v in order:
            sv = str(v)
            preds = list(G.predecessors(v))
            if preds:
                vals = []
                for p in preds:
                    sp = str(p)
                    if sp not in level:
                        # 关键：把缺键点直接打印出来
                        log.debug(f"[viz] level key missing: pred={sp} (v={sv}); adding default 0")
                        level[sp] = 0
                    vals.append(level.get(sp, 0))
                level[sv] = 1 + (max(vals) if vals else 0)
            else:
                level.setdefault(sv, 0)
    except Exception as e:
        log.debug(f"[viz] _compute_levels fallback: {e}")
    return level

def _to_graph_data(G: nx.DiGraph) -> Dict[str, Any]:
    levels = _compute_levels(G)
    nodes = []
    for n, d in G.nodes(data=True):
        nid = str(n)
        ntype = (d.get("type") or "unknown")
        lvl = int(levels.get(nid, 0))
        lane = int(d.get("lane", 0) or 0)
        label = d.get("label") or d.get("name") or nid
        nodes.append({
            "id": nid, 
            "label": str(label), 
            "type": str(ntype).lower(), 
            "level": lvl,
            "lane": lane,
            "ipi_source": bool(d.get("ipi_source", False)),
            "ipi_score": float(d.get("ipi_score", 0.0) or 0.0),
        })

    edges = []
    for u, v, ed in G.edges(data=True):
        edges.append({"from": str(u), "to": str(v), "type": str(ed.get("type", "control_flow"))})

    config = {
        "layout": "hierarchical",
        "hierarchical": {"direction": "LR", "levelSeparation": 170, "nodeSpacing": 140},
        "physics": True,
    }
    return {"nodes": nodes, "edges": edges, "config": config}


@router.post("/graph", response_model=GraphResponse)
async def get_graph_visualization(request: GraphRequest):
    try:
        G = GraphBuilder().build_from_prompt(request.user_input, request.external_data)
        # ✅ sanity check: ensure all edge endpoints are in nodes
        missing = []
        node_set = set(str(n) for n in G.nodes())
        for u, v in G.edges():
            if str(u) not in node_set:
                missing.append(("from", str(u)))
            if str(v) not in node_set:
                missing.append(("to", str(v)))
        if missing:
            log.error(f"[viz] graph has missing endpoints: {missing[:20]}")

        graph_data = _to_graph_data(G)

        # ✅ risk_scores：直接从外部数据判定风险，并绑定到 observation 节点
        risk_scores: Dict[str, float] = {}

        if request.external_data:
            rule_score = float(RuleEngine().check(request.external_data).get("score", 0.0))
            node_score = float(NodeEmbeddingDetector(use_semantic_model=False).detect(request.external_data).get("risk_score", 0.0))
            injection = max(rule_score, node_score)

            if injection > 0:
                for n, d in G.nodes(data=True):
                    if str(d.get("type", "")).lower() == "observation":
                        risk_scores[str(n)] = max(risk_scores.get(str(n), 0.0), injection)

        graph_data["risk_scores"] = risk_scores

        metrics = calculate_graph_metrics(G)
        metrics["external_data_source"] = request.external_data_source
        metrics["external_data_filename"] = request.external_data_filename

        return GraphResponse(graph_data=graph_data, metrics=metrics)

    except Exception as e:
        # ✅ 打印完整 traceback，下一次你就能看到 KeyError 发生在具体哪一行
        log.exception(f"[viz][EXCEPTION] {e}")
        raise HTTPException(status_code=500, detail=str(e))

