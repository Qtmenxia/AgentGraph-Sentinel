"""
污点传播分析 - 基于Spotlighting思想的图着色算法
"""
from typing import Dict, Set
import networkx as nx
from enum import Enum

class TrustLevel(Enum):
    """可信度级别"""
    TRUSTED = "green"      # 可信源（用户输入、内部数据库）
    NEUTRAL = "blue"       # 中性源（部分可信的API）
    UNTRUSTED = "red"      # 不可信源（Web搜索、外部文件）
    COMPROMISED = "black"  # 已被污染

class TaintAnalyzer:
    """污点传播分析器"""
    
    def __init__(self):
        """初始化分析器"""
        # 预定义工具的可信度
        self.tool_trust_levels = {
            'user_input': TrustLevel.TRUSTED,
            'internal_db': TrustLevel.TRUSTED,
            'rag_database': TrustLevel.NEUTRAL,
            'web_search': TrustLevel.UNTRUSTED,
            'web_fetch': TrustLevel.UNTRUSTED,
            'file_read': TrustLevel.UNTRUSTED,
            'email_receive': TrustLevel.UNTRUSTED,
        }
    
    def analyze_graph(self, G: nx.DiGraph) -> Dict[str, TrustLevel]:
        """
        对执行图进行污点分析
        
        Args:
            G: 执行图
        
        Returns:
            node_trust_levels: {node_id: TrustLevel}
        """
        node_trust = {}
        
        # 1. 初始化源节点的可信度
        for node, data in G.nodes(data=True):
            if data.get('type') == 'tool':
                tool_name = data.get('tool', 'unknown')
                node_trust[node] = self.tool_trust_levels.get(
                    tool_name, 
                    TrustLevel.NEUTRAL
                )
            else:
                node_trust[node] = TrustLevel.TRUSTED
        
        # 2. 传播污点（拓扑排序遍历）
        try:
            for node in nx.topological_sort(G):
                # 获取所有前驱节点的可信度
                predecessors = list(G.predecessors(node))
                
                if predecessors:
                    # 如果有任何不可信的前驱，当前节点也不可信
                    pred_levels = [node_trust.get(p, TrustLevel.TRUSTED) 
                                   for p in predecessors]
                    
                    # 取最低可信度
                    if TrustLevel.COMPROMISED in pred_levels:
                        node_trust[node] = TrustLevel.COMPROMISED
                    elif TrustLevel.UNTRUSTED in pred_levels:
                        node_trust[node] = TrustLevel.UNTRUSTED
                    elif TrustLevel.NEUTRAL in pred_levels:
                        # 如果当前节点是Action，且有NEUTRAL输入，保持当前级别
                        if node_trust.get(node) == TrustLevel.TRUSTED:
                            node_trust[node] = TrustLevel.NEUTRAL
        
        except nx.NetworkXError:
            # 如果图有环，使用简化策略
            pass
        
        return node_trust
    
    def apply_spotlighting(self, text: str, trust_level: TrustLevel) -> str:
        """
        应用Spotlighting技术 - 为不可信内容添加分隔符
        
        Args:
            text: 原始文本
            trust_level: 可信度
        
        Returns:
            处理后的文本
        """
        if trust_level == TrustLevel.UNTRUSTED:
            return f"<<<EXTERNAL_DATA>>>\n{text}\n<<</EXTERNAL_DATA>>>"
        elif trust_level == TrustLevel.COMPROMISED:
            return f"<<<POTENTIALLY_MALICIOUS>>>\n{text}\n<<</POTENTIALLY_MALICIOUS>>>"
        else:
            return text
    
    def get_risk_summary(self, node_trust: Dict[str, TrustLevel]) -> Dict:
        """生成风险摘要"""
        summary = {
            'total_nodes': len(node_trust),
            'trusted': 0,
            'neutral': 0,
            'untrusted': 0,
            'compromised': 0,
        }
        
        for level in node_trust.values():
            if level == TrustLevel.TRUSTED:
                summary['trusted'] += 1
            elif level == TrustLevel.NEUTRAL:
                summary['neutral'] += 1
            elif level == TrustLevel.UNTRUSTED:
                summary['untrusted'] += 1
            elif level == TrustLevel.COMPROMISED:
                summary['compromised'] += 1
        
        summary['risk_score'] = (
            summary['untrusted'] * 0.5 + summary['compromised'] * 1.0
        ) / max(summary['total_nodes'], 1)
        
        return summary