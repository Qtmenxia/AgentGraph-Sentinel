"""
图工具函数
"""
import networkx as nx
from typing import Dict, List, Tuple

def visualize_graph_data(G: nx.DiGraph) -> Dict:
    """
    将NetworkX图转换为可视化数据
    
    Args:
        G: NetworkX图
    
    Returns:
        可视化数据字典
    """
    nodes = []
    edges = []
    
    for node, data in G.nodes(data=True):
        nodes.append({
            'id': str(node),
            'label': data.get('label', str(node)),
            'type': data.get('type', 'unknown'),
            'color': _get_node_color(data)
        })
    
    for src, dst, data in G.edges(data=True):
        edges.append({
            'from': str(src),
            'to': str(dst),
            'label': data.get('label', ''),
            'type': data.get('type', 'default')
        })
    
    return {'nodes': nodes, 'edges': edges}

def _get_node_color(data: Dict) -> str:
    """根据节点类型获取颜色"""
    node_type = data.get('type', 'unknown')
    
    color_map = {
        'action': '#3498db',      # 蓝色
        'tool': '#2ecc71',        # 绿色
        'observation': '#f39c12', # 橙色
        'sanitizer': '#9b59b6',   # 紫色
        'user_input': '#1abc9c'   # 青色
    }
    
    return color_map.get(node_type, '#95a5a6')

def calculate_graph_metrics(G: nx.DiGraph) -> Dict:
    """
    计算图的统计指标
    
    Args:
        G: NetworkX图
    
    Returns:
        指标字典
    """
    metrics = {
        'num_nodes': G.number_of_nodes(),
        'num_edges': G.number_of_edges(),
        'avg_degree': sum(dict(G.degree()).values()) / max(G.number_of_nodes(), 1),
        'is_dag': nx.is_directed_acyclic_graph(G),
    }
    
    # 计算最长路径
    if metrics['is_dag']:
        try:
            metrics['longest_path'] = len(nx.dag_longest_path(G))
        except:
            metrics['longest_path'] = 0
    else:
        metrics['longest_path'] = 0
    
    return metrics