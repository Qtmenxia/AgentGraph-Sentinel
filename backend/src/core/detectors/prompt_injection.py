"""
提示词注入检测器

基于DeBERTa的提示词注入检测，支持直接和间接注入检测
"""

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from abc import ABC, abstractmethod

import torch
import numpy as np
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    pipeline,
)

from src.schemas.detection import (
    DetectionResult,
    DetectorType,
    SeverityLevel,
    ThreatCategory,
)
from src.utils.logger import logger, log_execution_time
from src.utils.config import get_config


class BaseDetector(ABC):
    """检测器基类"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.is_initialized = False
    
    @abstractmethod
    def initialize(self) -> None:
        """初始化检测器"""
        pass
    
    @abstractmethod
    def detect(self, text: str, context: Optional[str] = None) -> DetectionResult:
        """执行检测"""
        pass
    
    def batch_detect(self, texts: List[str]) -> List[DetectionResult]:
        """批量检测"""
        return [self.detect(text) for text in texts]


class RuleBasedDetector(BaseDetector):
    """基于规则的检测器"""
    
    # 高风险关键词模式
    HIGH_RISK_PATTERNS = [
        r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)",
        r"disregard\s+(all\s+)?(previous|above|prior)",
        r"forget\s+(all\s+)?(previous|above|prior|everything)",
        r"new\s+instruction[s]?:",
        r"system\s*:\s*",
        r"admin\s*:\s*",
        r"jailbreak",
        r"do\s+anything\s+now",
        r"dan\s+mode",
        r"developer\s+mode",
        r"ignore\s+safety",
        r"bypass\s+(security|filter|restriction)",
    ]
    
    # 中文高风险模式
    HIGH_RISK_PATTERNS_ZH = [
        r"忽略(之前|以上|所有)(的)?(指令|提示|规则)",
        r"无视(之前|以上|所有)(的)?(指令|提示|规则)",
        r"新(的)?指令[：:]",
        r"系统[：:]",
        r"管理员[：:]",
        r"越狱",
        r"绕过(安全|过滤|限制)",
    ]
    
    # 隐蔽注入模式
    COVERT_PATTERNS = [
        r"<\s*system\s*>",
        r"\[\s*INST\s*\]",
        r"```\s*system",
        r"###\s*instruction",
        r"<\|im_start\|>",
        r"<\|endoftext\|>",
        r"\\x[0-9a-fA-F]{2}",  # 十六进制编码
        r"&#\d+;",  # HTML实体编码
        r"%[0-9a-fA-F]{2}",  # URL编码
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.compiled_patterns: List[Tuple[re.Pattern, str, float]] = []
    
    def initialize(self) -> None:
        """编译正则表达式"""
        patterns_with_meta = [
            (self.HIGH_RISK_PATTERNS, "high_risk", 0.9),
            (self.HIGH_RISK_PATTERNS_ZH, "high_risk_zh", 0.85),
            (self.COVERT_PATTERNS, "covert", 0.8),
        ]
        
        for patterns, category, weight in patterns_with_meta:
            for pattern in patterns:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    self.compiled_patterns.append((compiled, category, weight))
                except re.error as e:
                    logger.warning(f"无效的正则表达式 {pattern}: {e}")
        
        self.is_initialized = True
        logger.info(f"规则检测器初始化完成，加载 {len(self.compiled_patterns)} 个模式")
    
    def detect(self, text: str, context: Optional[str] = None) -> DetectionResult:
        """执行规则检测"""
        if not self.is_initialized:
            self.initialize()
        
        start_time = time.perf_counter()
        
        matches = []
        max_confidence = 0.0
        
        # 合并文本和上下文
        full_text = text
        if context:
            full_text = f"{context}\n{text}"
        
        # 检查所有模式
        for pattern, category, weight in self.compiled_patterns:
            for match in pattern.finditer(full_text):
                matches.append({
                    "pattern": pattern.pattern,
                    "category": category,
                    "weight": weight,
                    "match": match.group(),
                    "position": match.span(),
                })
                max_confidence = max(max_confidence, weight)
        
        # 构建结果
        is_threat = len(matches) > 0
        
        latency = (time.perf_counter() - start_time) * 1000
        
        return DetectionResult(
            detector_type=DetectorType.PROMPT_INJECTION,
            is_threat=is_threat,
            confidence=max_confidence if is_threat else 0.0,
            severity=SeverityLevel.HIGH if max_confidence > 0.85 else (
                SeverityLevel.MEDIUM if max_confidence > 0.7 else SeverityLevel.LOW
            ),
            threat_category=ThreatCategory.INDIRECT_INJECTION if is_threat else None,
            description=f"检测到 {len(matches)} 个可疑模式" if is_threat else "未检测到威胁",
            evidence=[m["match"] for m in matches[:5]],  # 最多5个证据
            matched_patterns=[m["pattern"] for m in matches],
            latency_ms=latency,
        )


class MLDetector(BaseDetector):
    """基于ML的检测器（DeBERTa）"""
    
    def __init__(
        self,
        model_name: str = "ProtectAI/deberta-v3-base-prompt-injection-v2",
        threshold: float = 0.85,
        device: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(config)
        self.model_name = model_name
        self.threshold = threshold
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        
        self.model = None
        self.tokenizer = None
        self.classifier = None
    
    def initialize(self) -> None:
        """加载模型"""
        logger.info(f"加载检测模型: {self.model_name}")
        
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name
            )
            
            # 移动到指定设备
            self.model.to(self.device)
            self.model.eval()
            
            # 创建pipeline
            self.classifier = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                device=0 if self.device == "cuda" else -1,
                max_length=512,
                truncation=True,
            )
            
            self.is_initialized = True
            logger.info(f"检测模型加载完成，设备: {self.device}")
            
        except Exception as e:
            logger.error(f"加载模型失败: {e}")
            raise
    
    @log_execution_time
    def detect(self, text: str, context: Optional[str] = None) -> DetectionResult:
        """执行ML检测"""
        if not self.is_initialized:
            self.initialize()
        
        start_time = time.perf_counter()
        
        # 合并文本
        input_text = text
        if context:
            input_text = f"Context: {context}\n\nText: {text}"
        
        # 截断过长文本
        if len(input_text) > 2000:
            input_text = input_text[:2000]
        
        try:
            # 推理
            result = self.classifier(input_text)[0]
            
            # 解析结果
            label = result["label"]
            score = result["score"]
            
            # 判断是否为注入
            # 不同模型标签可能不同，需要适配
            is_injection = label.upper() in ["INJECTION", "1", "POSITIVE", "MALICIOUS"]
            confidence = score if is_injection else 1 - score
            
            is_threat = confidence >= self.threshold
            
        except Exception as e:
            logger.error(f"ML检测失败: {e}")
            is_threat = False
            confidence = 0.0
        
        latency = (time.perf_counter() - start_time) * 1000
        
        return DetectionResult(
            detector_type=DetectorType.PROMPT_INJECTION,
            is_threat=is_threat,
            confidence=confidence,
            severity=self._calculate_severity(confidence),
            threat_category=ThreatCategory.INDIRECT_INJECTION if is_threat else None,
            description=f"ML检测置信度: {confidence:.2%}" if is_threat else "ML检测未发现威胁",
            latency_ms=latency,
        )
    
    def _calculate_severity(self, confidence: float) -> SeverityLevel:
        """根据置信度计算严重程度"""
        if confidence >= 0.95:
            return SeverityLevel.CRITICAL
        elif confidence >= 0.85:
            return SeverityLevel.HIGH
        elif confidence >= 0.7:
            return SeverityLevel.MEDIUM
        elif confidence >= 0.5:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def batch_detect(self, texts: List[str]) -> List[DetectionResult]:
        """批量检测"""
        if not self.is_initialized:
            self.initialize()
        
        start_time = time.perf_counter()
        
        try:
            results = self.classifier(texts)
            
            detection_results = []
            for text, result in zip(texts, results):
                label = result["label"]
                score = result["score"]
                is_injection = label.upper() in ["INJECTION", "1", "POSITIVE", "MALICIOUS"]
                confidence = score if is_injection else 1 - score
                is_threat = confidence >= self.threshold
                
                detection_results.append(DetectionResult(
                    detector_type=DetectorType.PROMPT_INJECTION,
                    is_threat=is_threat,
                    confidence=confidence,
                    severity=self._calculate_severity(confidence),
                    threat_category=ThreatCategory.INDIRECT_INJECTION if is_threat else None,
                    description=f"ML检测置信度: {confidence:.2%}",
                ))
            
            return detection_results
            
        except Exception as e:
            logger.error(f"批量检测失败: {e}")
            return [self.detect(text) for text in texts]


class PromptInjectionDetector:
    """提示词注入检测器（组合规则和ML）"""
    
    def __init__(
        self,
        use_ml: bool = True,
        ml_model: str = "ProtectAI/deberta-v3-base-prompt-injection-v2",
        threshold: float = 0.85,
    ):
        self.use_ml = use_ml
        
        # 初始化规则检测器
        self.rule_detector = RuleBasedDetector()
        
        # 初始化ML检测器
        self.ml_detector = None
        if use_ml:
            self.ml_detector = MLDetector(
                model_name=ml_model,
                threshold=threshold,
            )
    
    def initialize(self) -> None:
        """初始化所有检测器"""
        self.rule_detector.initialize()
        if self.ml_detector:
            self.ml_detector.initialize()
    
    def detect(
        self,
        text: str,
        context: Optional[str] = None,
        use_ml: Optional[bool] = None,
    ) -> DetectionResult:
        """
        执行检测
        
        Args:
            text: 待检测文本
            context: 上下文
            use_ml: 是否使用ML（覆盖默认设置）
        
        Returns:
            检测结果
        """
        start_time = time.perf_counter()
        
        # 规则检测
        rule_result = self.rule_detector.detect(text, context)
        
        # ML检测
        ml_result = None
        should_use_ml = use_ml if use_ml is not None else self.use_ml
        
        if should_use_ml and self.ml_detector:
            ml_result = self.ml_detector.detect(text, context)
        
        # 合并结果
        if ml_result:
            # 取最高置信度
            if ml_result.confidence > rule_result.confidence:
                final_result = ml_result
            else:
                final_result = rule_result
            
            # 合并证据
            final_result.evidence = list(set(
                rule_result.evidence + (ml_result.evidence or [])
            ))
            final_result.matched_patterns = rule_result.matched_patterns
        else:
            final_result = rule_result
        
        # 更新延迟
        final_result.latency_ms = (time.perf_counter() - start_time) * 1000
        
        return final_result


# 单例模式
_detector_instance: Optional[PromptInjectionDetector] = None


def get_prompt_injection_detector() -> PromptInjectionDetector:
    """获取检测器实例"""
    global _detector_instance
    
    if _detector_instance is None:
        config = get_config()
        pi_config = config.detection.prompt_injection
        
        _detector_instance = PromptInjectionDetector(
            use_ml=pi_config.enabled,
            ml_model=pi_config.model,
            threshold=pi_config.threshold,
        )
    
    return _detector_instance


# 导出
__all__ = [
    "BaseDetector",
    "RuleBasedDetector",
    "MLDetector",
    "PromptInjectionDetector",
    "get_prompt_injection_detector",
]