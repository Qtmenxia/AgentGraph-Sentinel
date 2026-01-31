"""
API请求和响应数据模型
"""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field

from src.schemas.detection import (
    AggregatedDetectionResult,
    SeverityLevel,
    ThreatCategory,
)
from src.schemas.graph import ExecutionGraph


# =============================================================================
# 扫描API
# =============================================================================

class ScanMode(str, Enum):
    """扫描模式"""
    QUICK = "quick"  # 快速扫描（仅提示词注入检测）
    STANDARD = "standard"  # 标准扫描（提示词+图异常）
    DEEP = "deep"  # 深度扫描（全部检测器）


class TextScanRequest(BaseModel):
    """文本扫描请求"""
    text: str = Field(..., min_length=1, max_length=100000)
    context: Optional[str] = None
    mode: ScanMode = ScanMode.STANDARD
    
    # 可选配置
    detectors: Optional[List[str]] = None  # 指定检测器
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    
    class Config:
        json_schema_extra = {
            "example": {
                "text": "Please summarize the following document...",
                "mode": "standard",
                "threshold": 0.5
            }
        }


class ToolOutputScanRequest(BaseModel):
    """工具输出扫描请求"""
    tool_name: str
    tool_input: Dict[str, Any]
    tool_output: str
    
    # 上下文
    user_task: Optional[str] = None
    previous_outputs: List[str] = Field(default_factory=list)
    
    mode: ScanMode = ScanMode.STANDARD


class ConversationScanRequest(BaseModel):
    """对话扫描请求"""
    messages: List[Dict[str, str]]  # [{"role": "user/assistant", "content": "..."}]
    system_prompt: Optional[str] = None
    mode: ScanMode = ScanMode.STANDARD


class ScanResponse(BaseModel):
    """扫描响应"""
    request_id: str
    is_safe: bool
    confidence: float = Field(ge=0.0, le=1.0)
    
    # 威胁信息
    threat_detected: bool = False
    severity: SeverityLevel = SeverityLevel.INFO
    threat_category: Optional[ThreatCategory] = None
    
    # 详细结果
    detection_result: Optional[AggregatedDetectionResult] = None
    
    # 建议
    recommendation: str = "allow"
    warnings: List[str] = Field(default_factory=list)
    
    # 性能
    latency_ms: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.now)
    
    class Config:
        use_enum_values = True


# =============================================================================
# 防护API
# =============================================================================

class ProtectionMode(str, Enum):
    """防护模式"""
    MONITOR = "monitor"  # 仅监控，不阻断
    PROTECT = "protect"  # 检测到威胁时阻断
    STRICT = "strict"  # 严格模式，任何可疑内容都阻断


class ProtectRequest(BaseModel):
    """防护请求"""
    input_text: str
    mode: ProtectionMode = ProtectionMode.PROTECT
    
    # 配置
    enable_spotlighting: bool = True
    enable_sanitizer: bool = True
    enable_minimizer: bool = False


class ProtectResponse(BaseModel):
    """防护响应"""
    request_id: str
    original_text: str
    processed_text: str
    
    # 处理结果
    was_modified: bool = False
    was_blocked: bool = False
    modifications: List[str] = Field(default_factory=list)
    
    # 检测结果
    scan_result: Optional[ScanResponse] = None
    
    # 性能
    latency_ms: float = 0.0


# =============================================================================
# Agent执行API
# =============================================================================

class AgentExecuteRequest(BaseModel):
    """Agent执行请求"""
    task: str
    tools_enabled: Optional[List[str]] = None
    max_iterations: int = Field(default=10, ge=1, le=50)
    
    # 防护配置
    protection_mode: ProtectionMode = ProtectionMode.PROTECT
    capture_trace: bool = True


class ToolCallInfo(BaseModel):
    """工具调用信息"""
    tool_name: str
    tool_input: Dict[str, Any]
    tool_output: str
    
    # 安全信息
    trust_level: float
    risk_score: float
    was_sanitized: bool = False
    
    # 时序
    timestamp: datetime
    duration_ms: float


class AgentExecuteResponse(BaseModel):
    """Agent执行响应"""
    request_id: str
    task: str
    result: str
    
    # 执行状态
    completed: bool = False
    iterations: int = 0
    
    # 工具调用
    tool_calls: List[ToolCallInfo] = Field(default_factory=list)
    
    # 安全信息
    threats_detected: int = 0
    threats_blocked: int = 0
    
    # 执行图
    execution_graph: Optional[ExecutionGraph] = None
    
    # 性能
    total_latency_ms: float = 0.0


# =============================================================================
# 基准测试API
# =============================================================================

class BenchmarkType(str, Enum):
    """基准类型"""
    AGENTDOJO = "agentdojo"
    ASB = "asb"
    CUSTOM = "custom"


class BenchmarkRequest(BaseModel):
    """基准测试请求"""
    benchmark_type: BenchmarkType
    
    # AgentDojo配置
    agentdojo_suites: List[str] = Field(default_factory=lambda: ["workspace"])
    agentdojo_attacks: List[str] = Field(default_factory=lambda: ["important_instructions"])
    
    # ASB配置
    asb_scenarios: List[str] = Field(default_factory=lambda: ["direct_injection"])
    
    # 通用配置
    defense_enabled: bool = True
    max_samples: Optional[int] = None


class BenchmarkResult(BaseModel):
    """单个测试用例结果"""
    case_id: str
    task_description: str
    
    # 任务完成
    task_completed: bool
    task_output: str
    
    # 攻击状态
    has_attack: bool
    attack_type: Optional[str] = None
    attack_successful: bool = False
    attack_blocked: bool = False
    
    # 检测信息
    detection_triggered: bool = False
    detection_confidence: float = 0.0


class BenchmarkResponse(BaseModel):
    """基准测试响应"""
    request_id: str
    benchmark_type: BenchmarkType
    
    # 汇总指标
    utility_accuracy: float  # UA
    attack_success_rate: float  # ASR
    detection_rate: float  # 检测率
    false_positive_rate: float  # 误报率
    
    # 详细结果
    total_cases: int
    results: List[BenchmarkResult] = Field(default_factory=list)
    
    # 性能
    total_time_seconds: float = 0.0


# =============================================================================
# MCP扫描API
# =============================================================================

class MCPScanRequest(BaseModel):
    """MCP扫描请求"""
    mcp_server_path: Optional[str] = None
    mcp_server_url: Optional[str] = None
    mcp_config: Optional[Dict[str, Any]] = None


class MCPRiskItem(BaseModel):
    """MCP风险项"""
    risk_type: str  # tool_poisoning, data_exfiltration, etc.
    severity: SeverityLevel
    description: str
    location: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: str


class MCPScanResponse(BaseModel):
    """MCP扫描响应"""
    request_id: str
    mcp_server: str
    
    # 扫描结果
    is_safe: bool
    risk_score: float = Field(ge=0.0, le=1.0)
    
    # 风险列表
    risks: List[MCPRiskItem] = Field(default_factory=list)
    
    # 工具分析
    tools_analyzed: int = 0
    risky_tools: List[str] = Field(default_factory=list)
    
    # 性能
    latency_ms: float = 0.0


# =============================================================================
# 通用响应
# =============================================================================

class HealthResponse(BaseModel):
    """健康检查响应"""
    status: str = "healthy"
    version: str
    uptime_seconds: float
    components: Dict[str, str] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """错误响应"""
    error: str
    detail: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


# 导出
__all__ = [
    # 扫描
    "ScanMode",
    "TextScanRequest",
    "ToolOutputScanRequest", 
    "ConversationScanRequest",
    "ScanResponse",
    # 防护
    "ProtectionMode",
    "ProtectRequest",
    "ProtectResponse",
    # Agent
    "AgentExecuteRequest",
    "ToolCallInfo",
    "AgentExecuteResponse",
    # 基准测试
    "BenchmarkType",
    "BenchmarkRequest",
    "BenchmarkResult",
    "BenchmarkResponse",
    # MCP
    "MCPScanRequest",
    "MCPRiskItem",
    "MCPScanResponse",
    # 通用
    "HealthResponse",
    "ErrorResponse",
]