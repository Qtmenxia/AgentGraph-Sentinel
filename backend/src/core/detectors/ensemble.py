"""
集成检测器

组合多个检测器的结果，提供统一的检测接口
"""

import time
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.schemas.detection import (
    DetectionResult,
    AggregatedDetectionResult,
    DetectorType,
    SeverityLevel,
    ThreatCategory,
)
from src.schemas.graph import ExecutionGraph
from src.core.detectors.prompt_injection import (
    PromptInjectionDetector,
    get_prompt_injection_detector,
)
from src.core.detectors.graph_anomaly import (
    GraphAnomalyDetector,
    get_graph_anomaly_detector,
)
from src.utils.logger import logger, log_execution_time
from src.utils.config import get_config
from src.utils.metrics import get_metrics_collector, Timer


class EnsembleDetector:
    """
    集成检测器
    
    组合多个检测器：
    1. 提示词注入检测器 (规则 + ML)
    2. 图异常检测器 (模式匹配 + MELON + GNN)
    3. 污点分析 (可选)
    """
    
    def __init__(
        self,
        enable_prompt_injection: bool = True,
        enable_graph_anomaly: bool = True,
        enable_taint_analysis: bool = True,
        weights: Optional[Dict[str, float]] = None,
        parallel: bool = True,
    ):
        self.enable_prompt_injection = enable_prompt_injection
        self.enable_graph_anomaly = enable_graph_anomaly
        self.enable_taint_analysis = enable_taint_analysis
        self.parallel = parallel
        
        # 检测器权重
        self.weights = weights or {
            DetectorType.PROMPT_INJECTION: 0.4,
            DetectorType.GRAPH_ANOMALY: 0.4,
            DetectorType.TAINT_ANALYSIS: 0.2,
        }
        
        # 初始化检测器（延迟加载）
        self._pi_detector: Optional[PromptInjectionDetector] = None
        self._ga_detector: Optional[GraphAnomalyDetector] = None
        
        # 指标收集器
        self.metrics = get_metrics_collector()
    
    @property
    def prompt_injection_detector(self) -> PromptInjectionDetector:
        """获取提示词注入检测器"""
        if self._pi_detector is None:
            self._pi_detector = get_prompt_injection_detector()
        return self._pi_detector
    
    @property
    def graph_anomaly_detector(self) -> GraphAnomalyDetector:
        """获取图异常检测器"""
        if self._ga_detector is None:
            self._ga_detector = get_graph_anomaly_detector()
        return self._ga_detector
    
    def initialize(self) -> None:
        """初始化所有检测器"""
        if self.enable_prompt_injection:
            self.prompt_injection_detector.initialize()
        
        if self.enable_graph_anomaly:
            # 图异常检测器在首次使用时初始化
            pass
        
        logger.info("集成检测器初始化完成")
    
    @log_execution_time
    def detect(
        self,
        text: Optional[str] = None,
        context: Optional[str] = None,
        execution_graph: Optional[ExecutionGraph] = None,
        masked_graph: Optional[ExecutionGraph] = None,
        tool_outputs: Optional[List[str]] = None,
    ) -> AggregatedDetectionResult:
        """
        执行集成检测
        
        Args:
            text: 待检测文本
            context: 上下文
            execution_graph: 执行图
            masked_graph: 掩码执行图
            tool_outputs: 工具输出列表
        
        Returns:
            聚合检测结果
        """
        start_time = time.perf_counter()
        result = AggregatedDetectionResult()
        
        # 收集检测任务
        tasks = []
        
        if self.enable_prompt_injection and text:
            tasks.append(("prompt_injection", self._detect_prompt_injection, 
                         {"text": text, "context": context}))
        
        if self.enable_graph_anomaly and execution_graph:
            tasks.append(("graph_anomaly", self._detect_graph_anomaly,
                         {"execution_graph": execution_graph, "masked_graph": masked_graph}))
        
        if self.enable_prompt_injection and tool_outputs:
            # 检测工具输出中的注入
            for i, output in enumerate(tool_outputs):
                tasks.append((f"tool_output_{i}", self._detect_prompt_injection,
                             {"text": output, "context": context}))
        
        # 执行检测
        if self.parallel and len(tasks) > 1:
            detection_results = self._parallel_detect(tasks)
        else:
            detection_results = self._sequential_detect(tasks)
        
        # 聚合结果
        for det_result in detection_results:
            result.add_result(det_result)
        
        # 计算最终结果
        result.finalize(self.weights)
        result.total_latency_ms = (time.perf_counter() - start_time) * 1000
        
        # 记录指标
        self.metrics.record_latency("ensemble_detection", result.total_latency_ms)
        
        return result
    
    def _detect_prompt_injection(
        self,
        text: str,
        context: Optional[str] = None,
    ) -> DetectionResult:
        """执行提示词注入检测"""
        with Timer(self.metrics, "prompt_injection_detection"):
            return self.prompt_injection_detector.detect(text, context)
    
    def _detect_graph_anomaly(
        self,
        execution_graph: ExecutionGraph,
        masked_graph: Optional[ExecutionGraph] = None,
    ) -> DetectionResult:
        """执行图异常检测"""
        with Timer(self.metrics, "graph_anomaly_detection"):
            return self.graph_anomaly_detector.detect(
                execution_graph, masked_graph
            )
    
    def _parallel_detect(
        self,
        tasks: List[tuple],
    ) -> List[DetectionResult]:
        """并行执行检测"""
        results = []
        
        with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            futures = {}
            for task_name, func, kwargs in tasks:
                future = executor.submit(func, **kwargs)
                futures[future] = task_name
            
            for future in as_completed(futures):
                task_name = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"检测任务 {task_name} 失败: {e}")
        
        return results
    
    def _sequential_detect(
        self,
        tasks: List[tuple],
    ) -> List[DetectionResult]:
        """顺序执行检测"""
        results = []
        
        for task_name, func, kwargs in tasks:
            try:
                result = func(**kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"检测任务 {task_name} 失败: {e}")
        
        return results
    
    def quick_scan(self, text: str) -> DetectionResult:
        """
        快速扫描（仅提示词注入检测）
        
        Args:
            text: 待检测文本
        
        Returns:
            检测结果
        """
        return self._detect_prompt_injection(text)
    
    def deep_scan(
        self,
        text: str,
        execution_graph: ExecutionGraph,
        masked_graph: Optional[ExecutionGraph] = None,
    ) -> AggregatedDetectionResult:
        """
        深度扫描（全部检测器）
        
        Args:
            text: 待检测文本
            execution_graph: 执行图
            masked_graph: 掩码执行图
        
        Returns:
            聚合检测结果
        """
        return self.detect(
            text=text,
            execution_graph=execution_graph,
            masked_graph=masked_graph,
        )


class DetectorOrchestrator:
    """
    检测器编排器
    
    根据场景选择合适的检测策略
    """
    
    def __init__(self):
        self.ensemble = EnsembleDetector()
        self.config = get_config()
    
    def initialize(self) -> None:
        """初始化"""
        self.ensemble.initialize()
    
    def scan_text(
        self,
        text: str,
        mode: str = "standard",
    ) -> AggregatedDetectionResult:
        """
        扫描文本
        
        Args:
            text: 待检测文本
            mode: 扫描模式 (quick/standard/deep)
        
        Returns:
            检测结果
        """
        if mode == "quick":
            result = self.ensemble.quick_scan(text)
            aggregated = AggregatedDetectionResult()
            aggregated.add_result(result)
            aggregated.finalize()
            return aggregated
        else:
            return self.ensemble.detect(text=text)
    
    def scan_tool_output(
        self,
        tool_name: str,
        tool_output: str,
        user_task: Optional[str] = None,
    ) -> AggregatedDetectionResult:
        """
        扫描工具输出
        
        Args:
            tool_name: 工具名称
            tool_output: 工具输出
            user_task: 用户任务（用于上下文）
        
        Returns:
            检测结果
        """
        context = f"Tool: {tool_name}\nTask: {user_task}" if user_task else f"Tool: {tool_name}"
        return self.ensemble.detect(text=tool_output, context=context)
    
    def scan_conversation(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
    ) -> AggregatedDetectionResult:
        """
        扫描对话
        
        Args:
            messages: 消息列表
            system_prompt: 系统提示
        
        Returns:
            检测结果
        """
        # 提取所有用户和助手消息
        all_text = []
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            all_text.append(f"{role}: {content}")
        
        combined_text = "\n".join(all_text)
        
        return self.ensemble.detect(
            text=combined_text,
            context=system_prompt,
        )
    
    def scan_with_graph(
        self,
        execution_graph: ExecutionGraph,
        masked_graph: Optional[ExecutionGraph] = None,
        additional_text: Optional[str] = None,
    ) -> AggregatedDetectionResult:
        """
        使用执行图扫描
        
        Args:
            execution_graph: 执行图
            masked_graph: 掩码执行图
            additional_text: 额外文本
        
        Returns:
            检测结果
        """
        return self.ensemble.detect(
            text=additional_text,
            execution_graph=execution_graph,
            masked_graph=masked_graph,
        )


# 单例模式
_orchestrator_instance: Optional[DetectorOrchestrator] = None


def get_detector_orchestrator() -> DetectorOrchestrator:
    """获取检测器编排器实例"""
    global _orchestrator_instance
    
    if _orchestrator_instance is None:
        _orchestrator_instance = DetectorOrchestrator()
    
    return _orchestrator_instance


# 导出
__all__ = [
    "EnsembleDetector",
    "DetectorOrchestrator",
    "get_detector_orchestrator",
]