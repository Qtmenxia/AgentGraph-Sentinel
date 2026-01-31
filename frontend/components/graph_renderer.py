"""
图可视化组件
"""
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network
from typing import Dict, List
import tempfile
import os

def render_graph(graph_data: Dict, risk_scores: Dict = None):
    """
    渲染交互式图
    
    Args:
        graph_data: 图数据 {'nodes': [...], 'edges': [...]}
        risk_scores: 节点风险评分
    """
    # 创建Network对象
    net = Network(
        height="600px",
        width="100%",
        bgcolor="#ffffff",
        font_color="black",
        directed=True
    )
    
    # 设置物理引擎
    net.set_options("""
    {
        "physics": {
            "enabled": true,
            "hierarchicalRepulsion": {
                "centralGravity": 0.0,
                "springLength": 100,
                "springConstant": 0.01,
                "nodeDistance": 120,
                "damping": 0.09
            },
            "solver": "hierarchicalRepulsion"
        },
        "layout": {
            "hierarchical": {
                "enabled": true,
                "direction": "LR",
                "sortMethod": "directed"
            }
        }
    }
    """)
    
    # 添加节点
    risk_scores = risk_scores or {}
    for node in graph_data.get('nodes', []):
        node_id = node['id']
        label = node.get('label', node_id)
        node_type = node.get('type', 'unknown')
        
        # 根据风险评分设置颜色
        risk = risk_scores.get(node_id, 0.0)
        if risk > 0.7:
            color = '#e74c3c'  # 红色 - 高风险
        elif risk > 0.4:
            color = '#f39c12'  # 橙色 - 中风险
        else:
            color = node.get('color', '#3498db')  # 默认颜色
        
        # 节点大小根据风险调整
        size = 20 + (risk * 30)
        
        net.add_node(
            node_id,
            label=label,
            color=color,
            size=size,
            title=f"Type: {node_type}\nRisk: {risk:.2%}"
        )
    
    # 添加边
    for edge in graph_data.get('edges', []):
        net.add_edge(
            edge['from'],
            edge['to'],
            label=edge.get('label', ''),
            arrows='to'
        )
    
    # 生成HTML
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w') as f:
        html_file = f.name
        net.save_graph(html_file)
    
    # 读取HTML
    with open(html_file, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # 清理临时文件
    os.unlink(html_file)
    
    # 渲染
    components.html(html_content, height=650)