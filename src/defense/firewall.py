"""
自适应防火墙 - 基于风险评分动态调整防御策略
"""
from typing import Dict, Any
from enum import Enum

class DefenseLevel(Enum):
    """防御级别"""
    NONE = 0      # 无防御
    LOW = 1       # 低级防御(仅日志)
    MEDIUM = 2    # 中级防御(Sanitizer)
    HIGH = 3      # 高级防御(Sanitizer + 限流)
    CRITICAL = 4  # 严重防御(阻断)

class AdaptiveFirewall:
    """自适应防火墙"""
    
    def __init__(self):
        """初始化防火墙"""
        self.thresholds = {
            DefenseLevel.LOW: 0.3,
            DefenseLevel.MEDIUM: 0.5,
            DefenseLevel.HIGH: 0.7,
            DefenseLevel.CRITICAL: 0.9
        }
    
    def determine_defense_level(self, risk_score: float) -> DefenseLevel:
        """
        根据风险评分确定防御级别
        
        Args:
            risk_score: 风险评分 (0-1)
        
        Returns:
            防御级别
        """
        if risk_score >= self.thresholds[DefenseLevel.CRITICAL]:
            return DefenseLevel.CRITICAL
        elif risk_score >= self.thresholds[DefenseLevel.HIGH]:
            return DefenseLevel.HIGH
        elif risk_score >= self.thresholds[DefenseLevel.MEDIUM]:
            return DefenseLevel.MEDIUM
        elif risk_score >= self.thresholds[DefenseLevel.LOW]:
            return DefenseLevel.LOW
        else:
            return DefenseLevel.NONE
    
    def apply_defense(self, data: Any, level: DefenseLevel) -> Dict[str, Any]:
        """
        应用防御策略
        
        Args:
            data: 原始数据
            level: 防御级别
        
        Returns:
            防御结果
        """
        if level == DefenseLevel.NONE:
            return {
                'action': 'allow',
                'data': data,
                'message': 'No defense applied'
            }
        
        elif level == DefenseLevel.LOW:
            return {
                'action': 'log',
                'data': data,
                'message': 'Low risk detected, logging'
            }
        
        elif level == DefenseLevel.MEDIUM:
            return {
                'action': 'sanitize',
                'data': data,  # 实际应用Sanitizer
                'message': 'Medium risk, applying sanitizer'
            }
        
        elif level == DefenseLevel.HIGH:
            return {
                'action': 'sanitize_and_limit',
                'data': data,
                'message': 'High risk, sanitizing and rate limiting'
            }
        
        else:  # CRITICAL
            return {
                'action': 'block',
                'data': None,
                'message': 'Critical risk detected, blocking request'
            }
