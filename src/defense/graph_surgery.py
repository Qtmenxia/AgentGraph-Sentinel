"""
动态图手术 - 在检测到风险时实时修改执行图
"""
import networkx as nx
from typing import Dict, List
from .sanitizer import Sanitizer
from ..detection.taint_analysis import TrustLevel

class GraphSurgeon:
    """图手术执行器"""
    
    def __init__(self):
        """初始化手术器"""
        self.sanitizer = Sanitizer()
    
    def insert_firewall_nodes(
        self, 
        G: nx.DiGraph, 
        risk_scores: Dict[str, float],
        trust_levels: Dict[str, TrustLevel]
    ) -> nx.DiGraph:
        """
        在高风险边上插入Sanitizer节点
        
        Args:
            G: 原始执行图
            risk_scores: 节点风险评分
            trust_levels: 节点可信度
        
        Returns:
            修复后的图
        """
        G_new = G.copy()
        
        # 找到所有高风险的Observation节点
        high_risk_obs = [
            node for node, data in G.nodes(data=True)
            if (data.get('type') == 'observation' and 
                risk_scores.get(node, 0) > 0.6)
        ]
        
        insertion_count = 0
        
        for obs_node in high_risk_obs:
            # 找到该节点的所有后继边
            out_edges = list(G.out_edges(obs_node))
            
            for src, dst in out_edges:
                # 创建Sanitizer节点
                sanitizer_id = f"sanitizer_{insertion_count}"
                insertion_count += 1
                
                G_new.add_node(
                    sanitizer_id,
                    type='sanitizer',
                    function='clean_data',
                    inserted=True
                )
                
                # 重定向边
                G_new.remove_edge(src, dst)
                G_new.add_edge(src, sanitizer_id, type='data_flow')
                G_new.add_edge(sanitizer_id, dst, type='cleaned_flow')
        
        return G_new
    
    def execute_surgery(self, G: nx.DiGraph, node_data: Dict) -> Dict:
        """
        执行图手术并返回修复结果
        
        Args:
            G: 执行图
            node_data: 节点实际数据
        
        Returns:
            修复后的节点数据
        """
        cleaned_data = {}
        
        for node, data in G.nodes(data=True):
            if data.get('type') == 'sanitizer':
                # 获取前驱节点的数据
                predecessors = list(G.predecessors(node))
                if predecessors:
                    input_data = node_data.get(predecessors[0], '')
                    # 执行清洗
                    cleaned_data[node] = self.sanitizer.clean_data(input_data)
        
        return cleaned_data