"""
图节点和边的Schema定义
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from enum import Enum

class NodeType(str, Enum):
    """节点类型"""
    USER_INPUT = "user_input"
    ACTION = "action"
    TOOL = "tool"
    OBSERVATION = "observation"
    SANITIZER = "sanitizer"

class EdgeType(str, Enum):
    """边类型"""
    DATA_FLOW = "data_flow"
    CONTROL_FLOW = "control_flow"
    CLEANED_FLOW = "cleaned_flow"

class GraphNode(BaseModel):
    """图节点"""
    node_id: str
    node_type: NodeType
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0

class GraphEdge(BaseModel):
    """图边"""
    edge_id: str
    source: str
    target: str
    edge_type: EdgeType
    metadata: Dict[str, Any] = Field(default_factory=dict)