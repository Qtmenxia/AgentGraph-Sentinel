"""
图可视化组件
- 背景色：节点类型（Action/Tool/Observation）
- 边框色：风险等级（低/中/高）
- 节点大小：风险等级（小/中/大）
"""
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network
from typing import Dict
import tempfile
import os


_TYPE_BG = {
    "action": "#3498db",       # 蓝
    "tool": "#2ecc71",         # 绿
    "observation": "#f39c12",  # 橙
    "sanitizer": "#9b59b6",    # 紫
    "user_input": "#1abc9c",   # 青
    "unknown": "#95a5a6",
}

# 风险边框：绿(低) / 橙(中) / 红(高)
def _risk_border(risk: float) -> str:
    if risk >= 0.70:
        return "#e74c3c"
    if risk >= 0.40:
        return "#f39c12"
    return "#2ecc71"


def _risk_size(risk: float) -> int:
    # 让图例更“离散”：小/中/大
    if risk >= 0.70:
        return 42
    if risk >= 0.40:
        return 30
    return 22


def render_graph(graph_data: Dict, risk_scores: Dict = None):
    """
    渲染交互式图

    Args:
        graph_data: 图数据 {'nodes': [...], 'edges': [...]}
        risk_scores: 节点风险评分（0-1），用于边框+大小
    """
    net = Network(
        height="650px",
        width="100%",
        bgcolor="#ffffff",
        font_color="black",
        directed=True,
    )

    net.set_options(
        """
    {
      "physics": {
        "enabled": true,
        "hierarchicalRepulsion": {
          "centralGravity": 0.0,
          "springLength": 120,
          "springConstant": 0.01,
          "nodeDistance": 140,
          "damping": 0.09
        },
        "solver": "hierarchicalRepulsion",
        "stabilization": {"iterations": 200}
      },
      "layout": {
        "hierarchical": {
          "enabled": true,
          "direction": "LR",
          "sortMethod": "directed",
          "levelSeparation": 160,
          "nodeSpacing": 140
        }
      },
      "edges": {
        "smooth": {"type": "cubicBezier"},
        "arrows": {"to": {"enabled": true}}
      }
    }
    """
    )

    risk_scores = risk_scores or {}

    # Add nodes
    for node in graph_data.get("nodes", []):
        node_id = node["id"]
        label = node.get("label", node_id)
        node_type = (node.get("type", "unknown") or "unknown").lower()

        risk = float(risk_scores.get(node_id, 0.0) or 0.0)
        risk = max(0.0, min(1.0, risk))

        bg = _TYPE_BG.get(node_type, _TYPE_BG["unknown"])
        border = _risk_border(risk)
        size = _risk_size(risk)

        lane = int(node.get("lane", 0) or 0)
        level = int(node.get("level", 0) or 0)
        # 固定坐标：x=level, y=lane，让并行分支自然分开
        x = level * 220
        y = lane * 180

        # PyVis 颜色支持 background/border
        net.add_node(
            node_id,
            label=label,
            color={"background": bg, "border": border},
            borderWidth=3,
            x=x,
            y=y,
            size=size,
            fixed={"x": True, "y": True},
            title=(
                f"<b>{label}</b><br/>"
                f"Type: {node_type}<br/>"
                f"Risk: {risk:.0%}<br/>"
            ),
        )

    # Add edges
    for edge in graph_data.get("edges", []):
        etype = edge.get("type", "default")
        # data_flow 边更强调（虚线）
        dashed = True if etype == "data_flow" else False
        net.add_edge(
            edge["from"],
            edge["to"],
            label=edge.get("label", ""),
            arrows="to",
            dashes=dashed,
        )

    # Generate HTML
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8") as f:
        html_file = f.name
        net.save_graph(html_file)

    with open(html_file, "r", encoding="utf-8") as f:
        html_content = f.read()

    os.unlink(html_file)

    components.html(html_content, height=700, scrolling=True)
