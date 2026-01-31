"""
检测结果数据模型
"""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """风险严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DetectorType(str, Enum):
    """检测器类型"""
    PROMPT_INJECTION = "prompt_injection"
    GRAPH_ANOMALY = "graph_anomaly"
    TAINT_ANALYSIS = "taint_analysis"
    PATTERN_MATCH = "pattern_match"
    ENSEMBLE = "ensemble"


class ThreatCategory(str, Enum):
    """威胁类别"""
    INDIRECT_INJECTION = "indirect_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TOOL_MANIPULATION = "tool_manipulation"
    RAG_POISONING = "rag_poisoning"
    UNKNOWN = "unknown"


class DetectionResult(BaseModel):
    """单个检测器的检测结果"""
    detector_type: DetectorType
    is_threat: bool = False
    confidence: float = Field(ge=0.0, le=1.0, description="检测置信度")
    severity: SeverityLevel = SeverityLevel.INFO
    threat_category: Optional[ThreatCategory] = None
    
    # 详细信息
    description: str = ""
    evidence: List[str] = Field(default_factory=list)
    matched_patterns: List[str] = Field(default_factory=list)
    
    # 定位信息
    location: Optional[Dict[str, Any]] = None  # 在执行图中的位置
    
    # 元数据
    latency_ms: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.now)
    
    class Config:
        use_enum_values = True


class AggregatedDetectionResult(BaseModel):
    """聚合检测结果"""
    # 总体判定
    is_threat: bool = False
    final_confidence: float = Field(ge=0.0, le=1.0)
    highest_severity: SeverityLevel = SeverityLevel.INFO
    primary_threat: Optional[ThreatCategory] = None
    
    # 各检测器结果
    detector_results: List[DetectionResult] = Field(default_factory=list)
    
    # 建议操作
    recommended_action: str = "allow"  # allow, warn, block
    
    # 聚合统计
    threat_count: int = 0
    detectors_triggered: List[str] = Field(default_factory=list)
    
    # 性能
    total_latency_ms: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.now)
    
    class Config:
        use_enum_values = True
    
    def add_result(self, result: DetectionResult) -> None:
        """添加检测器结果"""
        self.detector_results.append(result)
        
        if result.is_threat:
            self.threat_count += 1
            self.detectors_triggered.append(result.detector_type)
            
            # 更新最高严重程度
            severity_order = [
                SeverityLevel.INFO,
                SeverityLevel.LOW,
                SeverityLevel.MEDIUM,
                SeverityLevel.HIGH,
                SeverityLevel.CRITICAL,
            ]
            if severity_order.index(result.severity) > severity_order.index(self.highest_severity):
                self.highest_severity = result.severity
                self.primary_threat = result.threat_category
        
        self.total_latency_ms += result.latency_ms
    
    def finalize(self, weights: Optional[Dict[str, float]] = None) -> None:
        """计算最终结果"""
        if not self.detector_results:
            return
        
        # 默认权重
        if weights is None:
            weights = {
                DetectorType.PROMPT_INJECTION: 0.4,
                DetectorType.GRAPH_ANOMALY: 0.4,
                DetectorType.TAINT_ANALYSIS: 0.2,
            }
        
        # 计算加权置信度
        weighted_sum = 0.0
        weight_total = 0.0
        
        for result in self.detector_results:
            w = weights.get(result.detector_type, 0.25)
            weighted_sum += result.confidence * w * (1 if result.is_threat else 0)
            weight_total += w
        
        self.final_confidence = weighted_sum / weight_total if weight_total > 0 else 0.0
        
        # 判定是否为威胁
        self.is_threat = self.final_confidence > 0.5 or any(
            r.is_threat and r.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
            for r in self.detector_results
        )
        
        # 决定推荐操作
        if self.highest_severity == SeverityLevel.CRITICAL:
            self.recommended_action = "block"
        elif self.highest_severity == SeverityLevel.HIGH:
            self.recommended_action = "block"
        elif self.is_threat:
            self.recommended_action = "warn"
        else:
            self.recommended_action = "allow"


class TaintLabel(BaseModel):
    """污点标签"""
    source: str  # 数据来源
    trust_level: float = Field(ge=0.0, le=1.0)
    is_tainted: bool = False
    propagation_path: List[str] = Field(default_factory=list)
    
    def propagate(self, new_source: str, decay: float = 0.9) -> "TaintLabel":
        """传播污点"""
        new_label = TaintLabel(
            source=new_source,
            trust_level=self.trust_level * decay,
            is_tainted=self.is_tainted or self.trust_level < 0.5,
            propagation_path=self.propagation_path + [new_source]
        )
        return new_label


class TaintAnalysisResult(BaseModel):
    """污点分析结果"""
    data_id: str
    labels: List[TaintLabel] = Field(default_factory=list)
    min_trust_level: float = 1.0
    is_contaminated: bool = False
    contamination_sources: List[str] = Field(default_factory=list)
    
    def analyze(self) -> None:
        """分析污点状态"""
        if not self.labels:
            return
        
        self.min_trust_level = min(l.trust_level for l in self.labels)
        self.is_contaminated = any(l.is_tainted for l in self.labels)
        self.contamination_sources = [
            l.source for l in self.labels if l.is_tainted
        ]


class PatternMatchResult(BaseModel):
    """模式匹配结果"""
    pattern_name: str
    pattern_category: str
    matched: bool = False
    similarity_score: float = 0.0
    matched_nodes: List[str] = Field(default_factory=list)
    matched_edges: List[tuple] = Field(default_factory=list)
    description: str = ""
    indicators: List[str] = Field(default_factory=list)


# 导出
__all__ = [
    "SeverityLevel",
    "DetectorType",
    "ThreatCategory",
    "DetectionResult",
    "AggregatedDetectionResult",
    "TaintLabel",
    "TaintAnalysisResult",
    "PatternMatchResult",
]