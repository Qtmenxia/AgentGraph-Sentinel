"""
执行图数据模型
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
import uuid


class NodeType(str, Enum):
    """节点类型"""
    USER_INPUT = "user_input"
    SYSTEM_PROMPT = "system_prompt"
    LLM_CALL = "llm_call"
    LLM_DECISION = "llm_decision"
    TOOL_CALL = "tool_call"
    TOOL_OUTPUT = "tool_output"
    OBSERVATION = "observation"
    MEMORY_ACCESS = "memory_access"
    RAG_RETRIEVAL = "rag_retrieval"
    MCP_CALL = "mcp_call"
    AGENT_OUTPUT = "agent_output"
    FIREWALL = "firewall"
    SANITIZER = "sanitizer"


class EdgeType(str, Enum):
    """边类型"""
    DATA_FLOW = "data_flow"
    CONTROL_FLOW = "control_flow"
    PARAMETER_INJECTION = "parameter_injection"
    CONTEXT = "context"
    RETRIEVAL = "retrieval"
    OUTPUT = "output"
    INFLUENCE = "influence"
    DIRECT = "direct"
    INTERCEPT = "intercept"
    RECURSIVE = "recursive"


class TrustLevel(str, Enum):
    """信任等级"""
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"
    MALICIOUS = "malicious"


class GraphNode(BaseModel):
    """执行图节点"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    node_type: NodeType
    name: str = ""
    
    # 内容信息
    content: Optional[str] = None
    content_hash: Optional[str] = None
    content_length: int = 0
    
    # 工具调用特定字段
    tool_name: Optional[str] = None
    tool_parameters: Optional[Dict[str, Any]] = None
    tool_result: Optional[str] = None
    
    # LLM调用特定字段
    model_name: Optional[str] = None
    tokens_used: int = 0
    
    # 信任和风险
    trust_level: float = Field(default=1.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    is_tainted: bool = False
    taint_sources: List[str] = Field(default_factory=list)
    
    # 时序信息
    timestamp: datetime = Field(default_factory=datetime.now)
    duration_ms: float = 0.0
    sequence_number: int = 0
    
    # 元数据
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True
    
    def to_feature_vector(self) -> List[float]:
        """转换为特征向量（用于GNN）"""
        # 节点类型one-hot编码
        type_features = [0.0] * len(NodeType)
        type_index = list(NodeType).index(self.node_type)
        type_features[type_index] = 1.0
        
        # 数值特征
        numeric_features = [
            self.trust_level,
            self.risk_score,
            1.0 if self.is_tainted else 0.0,
            min(self.content_length / 10000, 1.0),  # 归一化
            self.tokens_used / 4096 if self.tokens_used else 0.0,
            self.duration_ms / 1000 if self.duration_ms else 0.0,
        ]
        
        return type_features + numeric_features


class GraphEdge(BaseModel):
    """执行图边"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    source_id: str
    target_id: str
    edge_type: EdgeType
    
    # 数据流信息
    data_size: int = 0
    data_hash: Optional[str] = None
    
    # 权重和置信度
    weight: float = 1.0
    confidence: float = 1.0
    
    # 污点传播
    taint_propagated: bool = False
    trust_decay: float = 0.0
    
    # 元数据
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
    
    class Config:
        use_enum_values = True


class ExecutionGraph(BaseModel):
    """执行图"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    
    # 图结构
    nodes: Dict[str, GraphNode] = Field(default_factory=dict)
    edges: List[GraphEdge] = Field(default_factory=list)
    
    # 特殊节点索引
    root_node_id: Optional[str] = None
    sink_node_ids: List[str] = Field(default_factory=list)
    
    # 统计信息
    node_count: int = 0
    edge_count: int = 0
    max_depth: int = 0
    
    # 时间范围
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # 元数据
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def add_node(self, node: GraphNode) -> str:
        """添加节点"""
        self.nodes[node.id] = node
        self.node_count = len(self.nodes)
        
        # 设置序列号
        node.sequence_number = self.node_count
        
        # 更新根节点
        if self.root_node_id is None:
            self.root_node_id = node.id
        
        return node.id
    
    def add_edge(self, edge: GraphEdge) -> str:
        """添加边"""
        # 验证节点存在
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            raise ValueError(f"节点不存在: {edge.source_id} -> {edge.target_id}")
        
        self.edges.append(edge)
        self.edge_count = len(self.edges)
        
        return edge.id
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """获取节点"""
        return self.nodes.get(node_id)
    
    def get_neighbors(self, node_id: str, direction: str = "out") -> List[str]:
        """获取邻居节点"""
        neighbors = []
        for edge in self.edges:
            if direction == "out" and edge.source_id == node_id:
                neighbors.append(edge.target_id)
            elif direction == "in" and edge.target_id == node_id:
                neighbors.append(edge.source_id)
            elif direction == "both":
                if edge.source_id == node_id:
                    neighbors.append(edge.target_id)
                elif edge.target_id == node_id:
                    neighbors.append(edge.source_id)
        return neighbors
    
    def get_edges_between(self, source_id: str, target_id: str) -> List[GraphEdge]:
        """获取两节点之间的边"""
        return [
            e for e in self.edges 
            if e.source_id == source_id and e.target_id == target_id
        ]
    
    def get_tool_call_nodes(self) -> List[GraphNode]:
        """获取所有工具调用节点"""
        return [
            n for n in self.nodes.values() 
            if n.node_type == NodeType.TOOL_CALL
        ]
    
    def get_tainted_nodes(self) -> List[GraphNode]:
        """获取所有被污染的节点"""
        return [n for n in self.nodes.values() if n.is_tainted]
    
    def get_high_risk_nodes(self, threshold: float = 0.7) -> List[GraphNode]:
        """获取高风险节点"""
        return [n for n in self.nodes.values() if n.risk_score >= threshold]
    
    def to_adjacency_list(self) -> Dict[str, List[str]]:
        """转换为邻接表"""
        adj = {node_id: [] for node_id in self.nodes}
        for edge in self.edges:
            adj[edge.source_id].append(edge.target_id)
        return adj
    
    def to_networkx(self):
        """转换为NetworkX图"""
        import networkx as nx
        
        G = nx.DiGraph()
        
        # 添加节点
        for node_id, node in self.nodes.items():
            G.add_node(
                node_id,
                node_type=node.node_type,
                name=node.name,
                trust_level=node.trust_level,
                risk_score=node.risk_score,
                is_tainted=node.is_tainted,
                tool_name=node.tool_name,
                sequence_number=node.sequence_number,
            )
        
        # 添加边
        for edge in self.edges:
            G.add_edge(
                edge.source_id,
                edge.target_id,
                edge_type=edge.edge_type,
                weight=edge.weight,
                taint_propagated=edge.taint_propagated,
            )
        
        return G


class AttackPattern(BaseModel):
    """攻击模式定义"""
    name: str
    description: str
    severity: str  # critical, high, medium, low
    category: str
    
    # 模式图结构
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    
    # 匹配条件
    indicators: List[str] = Field(default_factory=list)
    missing_nodes: List[Dict[str, Any]] = Field(default_factory=list)
    
    # 元数据
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def to_networkx(self):
        """转换为NetworkX图用于匹配"""
        import networkx as nx
        
        G = nx.DiGraph()
        
        for node in self.nodes:
            G.add_node(node["id"], **{k: v for k, v in node.items() if k != "id"})
        
        for edge in self.edges:
            G.add_edge(edge["from"], edge["to"], **{k: v for k, v in edge.items() if k not in ["from", "to"]})
        
        return G


class GraphDiff(BaseModel):
    """图差异"""
    added_nodes: List[str] = Field(default_factory=list)
    removed_nodes: List[str] = Field(default_factory=list)
    added_edges: List[Tuple[str, str]] = Field(default_factory=list)
    removed_edges: List[Tuple[str, str]] = Field(default_factory=list)
    modified_nodes: List[str] = Field(default_factory=list)
    
    # 差异指标
    graph_edit_distance: int = 0
    similarity_score: float = 1.0
    
    def is_significant(self, threshold: int = 3) -> bool:
        """判断差异是否显著"""
        return self.graph_edit_distance > threshold


# 导出
__all__ = [
    "NodeType",
    "EdgeType", 
    "TrustLevel",
    "GraphNode",
    "GraphEdge",
    "ExecutionGraph",
    "AttackPattern",
    "GraphDiff",
]