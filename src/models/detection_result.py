"""
检测结果模型
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class DetectionResult(BaseModel):
    """检测结果"""
    is_attack: bool
    confidence: float = Field(ge=0.0, le=1.0)
    detection_method: str
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)

class ComprehensiveDetectionResult(BaseModel):
    """综合检测结果"""
    trace_id: str
    is_attack: bool
    overall_risk_score: float
    
    # 各检测器结果
    graph_anomaly_result: Optional[DetectionResult] = None
    node_embedding_result: Optional[DetectionResult] = None
    taint_analysis_result: Optional[DetectionResult] = None
    rule_engine_result: Optional[DetectionResult] = None
    
    # 图数据
    graph_metrics: Dict[str, Any] = Field(default_factory=dict)
    high_risk_nodes: List[str] = Field(default_factory=list)
    
    # 防御建议
    recommended_action: str = "allow"  # 'allow', 'sanitize', 'block'
    
    # 外部数据元信息（用于后续可视化 / 审计）
    external_data_source: Optional[str] = None   # 'manual' | 'file' | 'demo' 等
    external_data_filename: Optional[str] = None
    
    timestamp: datetime = Field(default_factory=datetime.now)