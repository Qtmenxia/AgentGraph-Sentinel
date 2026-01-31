"""
AgentShield - 基于动态执行图的AI Agent全链路可信防护系统

核心模块:
- detectors: 检测器模块 (提示词注入、图异常检测)
- graph: 图计算模块 (执行图构建、模式匹配、GNN)
- guardrails: 防护栏模块 (输入/输出防护、污点追踪)
- firewall: 动态防火墙模块 (节点注入、数据清洗)
- agents: Agent集成模块 (LangGraph集成)
"""

__version__ = "0.1.0"
__author__ = "CISCN 2026 Team"

from src.utils.config import get_config, Settings

__all__ = ["get_config", "Settings", "__version__"]