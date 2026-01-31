"""
指标计算模块

用于计算检测性能、评测指标等
"""

import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime
import threading

import numpy as np


@dataclass
class DetectionMetrics:
    """检测指标"""
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    
    @property
    def precision(self) -> float:
        """精确率"""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def recall(self) -> float:
        """召回率"""
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        """F1分数"""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def accuracy(self) -> float:
        """准确率"""
        total = (self.true_positives + self.false_positives + 
                 self.true_negatives + self.false_negatives)
        correct = self.true_positives + self.true_negatives
        return correct / total if total > 0 else 0.0
    
    @property
    def false_positive_rate(self) -> float:
        """误报率"""
        total = self.false_positives + self.true_negatives
        return self.false_positives / total if total > 0 else 0.0
    
    def update(self, predicted: bool, actual: bool) -> None:
        """更新指标"""
        if predicted and actual:
            self.true_positives += 1
        elif predicted and not actual:
            self.false_positives += 1
        elif not predicted and actual:
            self.false_negatives += 1
        else:
            self.true_negatives += 1
    
    def to_dict(self) -> Dict[str, float]:
        """转换为字典"""
        return {
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "accuracy": self.accuracy,
            "false_positive_rate": self.false_positive_rate,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
        }


@dataclass
class LatencyMetrics:
    """延迟指标"""
    samples: List[float] = field(default_factory=list)
    
    def add_sample(self, latency_ms: float) -> None:
        """添加样本"""
        self.samples.append(latency_ms)
    
    @property
    def mean(self) -> float:
        """平均延迟"""
        return np.mean(self.samples) if self.samples else 0.0
    
    @property
    def median(self) -> float:
        """中位数延迟"""
        return np.median(self.samples) if self.samples else 0.0
    
    @property
    def p95(self) -> float:
        """P95延迟"""
        return np.percentile(self.samples, 95) if self.samples else 0.0
    
    @property
    def p99(self) -> float:
        """P99延迟"""
        return np.percentile(self.samples, 99) if self.samples else 0.0
    
    @property
    def std(self) -> float:
        """标准差"""
        return np.std(self.samples) if self.samples else 0.0
    
    def to_dict(self) -> Dict[str, float]:
        """转换为字典"""
        return {
            "mean_ms": self.mean,
            "median_ms": self.median,
            "p95_ms": self.p95,
            "p99_ms": self.p99,
            "std_ms": self.std,
            "sample_count": len(self.samples),
        }


@dataclass 
class BenchmarkMetrics:
    """评测基准指标"""
    # 效用指标
    utility_accuracy: float = 0.0  # UA: 无攻击时任务完成率
    
    # 安全指标
    attack_success_rate: float = 0.0  # ASR: 攻击成功率
    targeted_asr: float = 0.0  # 特定目标攻击成功率
    
    # 详细统计
    total_tasks: int = 0
    completed_tasks: int = 0
    blocked_attacks: int = 0
    missed_attacks: int = 0
    
    def to_dict(self) -> Dict[str, float]:
        """转换为字典"""
        return {
            "utility_accuracy": self.utility_accuracy,
            "attack_success_rate": self.attack_success_rate,
            "targeted_asr": self.targeted_asr,
            "total_tasks": self.total_tasks,
            "completed_tasks": self.completed_tasks,
            "blocked_attacks": self.blocked_attacks,
            "missed_attacks": self.missed_attacks,
        }


class MetricsCollector:
    """指标收集器"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._detection_metrics: Dict[str, DetectionMetrics] = defaultdict(DetectionMetrics)
        self._latency_metrics: Dict[str, LatencyMetrics] = defaultdict(LatencyMetrics)
        self._counters: Dict[str, int] = defaultdict(int)
        self._start_time = time.time()
    
    def record_detection(
        self, 
        detector_name: str, 
        predicted: bool, 
        actual: bool
    ) -> None:
        """记录检测结果"""
        with self._lock:
            self._detection_metrics[detector_name].update(predicted, actual)
    
    def record_latency(self, operation: str, latency_ms: float) -> None:
        """记录延迟"""
        with self._lock:
            self._latency_metrics[operation].add_sample(latency_ms)
    
    def increment_counter(self, name: str, value: int = 1) -> None:
        """增加计数器"""
        with self._lock:
            self._counters[name] += value
    
    def get_detection_metrics(self, detector_name: str) -> DetectionMetrics:
        """获取检测指标"""
        with self._lock:
            return self._detection_metrics[detector_name]
    
    def get_latency_metrics(self, operation: str) -> LatencyMetrics:
        """获取延迟指标"""
        with self._lock:
            return self._latency_metrics[operation]
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """获取所有指标"""
        with self._lock:
            uptime = time.time() - self._start_time
            return {
                "uptime_seconds": uptime,
                "detection": {
                    name: metrics.to_dict() 
                    for name, metrics in self._detection_metrics.items()
                },
                "latency": {
                    name: metrics.to_dict()
                    for name, metrics in self._latency_metrics.items()
                },
                "counters": dict(self._counters),
            }
    
    def reset(self) -> None:
        """重置所有指标"""
        with self._lock:
            self._detection_metrics.clear()
            self._latency_metrics.clear()
            self._counters.clear()
            self._start_time = time.time()


class Timer:
    """计时器上下文管理器"""
    
    def __init__(self, collector: MetricsCollector, operation: str):
        self.collector = collector
        self.operation = operation
        self.start_time: Optional[float] = None
    
    def __enter__(self) -> "Timer":
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.start_time is not None:
            elapsed_ms = (time.perf_counter() - self.start_time) * 1000
            self.collector.record_latency(self.operation, elapsed_ms)


def calculate_asr(
    attack_results: List[Dict[str, Any]],
    target_tool: Optional[str] = None
) -> Tuple[float, float]:
    """
    计算攻击成功率
    
    Args:
        attack_results: 攻击结果列表
        target_tool: 目标工具名（用于计算targeted ASR）
    
    Returns:
        (ASR, Targeted ASR)
    """
    if not attack_results:
        return 0.0, 0.0
    
    total_attacks = len(attack_results)
    successful_attacks = sum(1 for r in attack_results if r.get("attack_successful", False))
    
    asr = successful_attacks / total_attacks
    
    # 计算特定目标ASR
    targeted_asr = 0.0
    if target_tool:
        targeted_results = [
            r for r in attack_results 
            if r.get("target_tool") == target_tool
        ]
        if targeted_results:
            targeted_successful = sum(
                1 for r in targeted_results if r.get("attack_successful", False)
            )
            targeted_asr = targeted_successful / len(targeted_results)
    
    return asr, targeted_asr


def calculate_utility(
    task_results: List[Dict[str, Any]],
    with_defense: bool = True
) -> float:
    """
    计算效用准确率
    
    Args:
        task_results: 任务结果列表
        with_defense: 是否启用防御
    
    Returns:
        UA (Utility Accuracy)
    """
    if not task_results:
        return 0.0
    
    # 过滤无攻击的任务
    clean_tasks = [
        r for r in task_results 
        if not r.get("has_attack", False)
    ]
    
    if not clean_tasks:
        return 0.0
    
    completed = sum(1 for r in clean_tasks if r.get("task_completed", False))
    return completed / len(clean_tasks)


# 全局指标收集器实例
_global_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """获取全局指标收集器"""
    global _global_collector
    if _global_collector is None:
        _global_collector = MetricsCollector()
    return _global_collector


# 导出
__all__ = [
    "DetectionMetrics",
    "LatencyMetrics", 
    "BenchmarkMetrics",
    "MetricsCollector",
    "Timer",
    "calculate_asr",
    "calculate_utility",
    "get_metrics_collector",
]