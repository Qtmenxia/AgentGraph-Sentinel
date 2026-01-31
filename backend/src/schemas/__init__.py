"""
数据模型模块

定义检测结果、图结构、API请求响应等数据模型
"""

from src.schemas.detection import (
    SeverityLevel,
    DetectorType,
    ThreatCategory,
    DetectionResult,
    AggregatedDetectionResult,
    TaintLabel,
    TaintAnalysisResult,
    PatternMatchResult,
)

from src.schemas.graph import (
    NodeType,
    EdgeType,
    TrustLevel,
    GraphNode,
    GraphEdge,
    ExecutionGraph,
    AttackPattern,
    GraphDiff,
)

from src.schemas.request import (
    ScanMode,
    TextScanRequest,
    ToolOutputScanRequest,
    ConversationScanRequest,
    ScanResponse,
    ProtectionMode,
    ProtectRequest,
    ProtectResponse,
    AgentExecuteRequest,
    ToolCallInfo,
    AgentExecuteResponse,
    BenchmarkType,
    BenchmarkRequest,
    BenchmarkResult,
    BenchmarkResponse,
    MCPScanRequest,
    MCPRiskItem,
    MCPScanResponse,
    HealthResponse,
    ErrorResponse,
)

__all__ = [
    # Detection
    "SeverityLevel",
    "DetectorType",
    "ThreatCategory",
    "DetectionResult",
    "AggregatedDetectionResult",
    "TaintLabel",
    "TaintAnalysisResult",
    "PatternMatchResult",
    # Graph
    "NodeType",
    "EdgeType",
    "TrustLevel",
    "GraphNode",
    "GraphEdge",
    "ExecutionGraph",
    "AttackPattern",
    "GraphDiff",
    # Request/Response
    "ScanMode",
    "TextScanRequest",
    "ToolOutputScanRequest",
    "ConversationScanRequest",
    "ScanResponse",
    "ProtectionMode",
    "ProtectRequest",
    "ProtectResponse",
    "AgentExecuteRequest",
    "ToolCallInfo",
    "AgentExecuteResponse",
    "BenchmarkType",
    "BenchmarkRequest",
    "BenchmarkResult",
    "BenchmarkResponse",
    "MCPScanRequest",
    "MCPRiskItem",
    "MCPScanResponse",
    "HealthResponse",
    "ErrorResponse",
]