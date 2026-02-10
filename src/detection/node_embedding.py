"""
节点嵌入检测器 - 在Observation节点植入检测器
基于InstructDetector思想的实现
"""
import re
from typing import Tuple, Dict
from transformers import pipeline
import torch

class NodeEmbeddingDetector:
    """节点嵌入检测器 - 检测工具返回结果中的恶意指令"""
    
    def __init__(self):
        """初始化检测器"""
        # 使用轻量级的零样本分类器
        try:
            self.classifier = pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli",
                device=0 if torch.cuda.is_available() else -1
            )
        except Exception as e:
            print(f"Warning: Could not load ML model: {e}")
            self.classifier = None
        
        # 恶意模式规则库
        self.malicious_patterns = [
            r"ignore\s+previous\s+instructions",
            r"disregard\s+all\s+prior",
            r"new\s+instructions:",
            r"system:\s*you\s+are\s+now",
            r"forget\s+everything",
            r"start\s+over",
            r"instead,\s+do\s+the\s+following",
            r"however,\s+your\s+new\s+task\s+is",
        ]
    
    def scan_observation_node(self, text: str, node_metadata: Dict = None) -> Tuple[bool, float, Dict]:
        """
        扫描Observation节点的内容
        
        Args:
            text: 工具返回的文本内容
            node_metadata: 节点元数据（工具名称、时间戳等）
        
        Returns:
            (is_malicious, confidence, details)
        """
        # 1. 规则快速检测
        rule_result = self._rule_based_check(text)
        if rule_result['is_malicious']:
            return True, rule_result['confidence'], rule_result
        
        # 2. ML模型检测（如果可用）
        if self.classifier:
            ml_result = self._ml_based_check(text)
            if ml_result['is_malicious']:
                return True, ml_result['confidence'], ml_result
        
        # 3. 组合判定
        return False, 0.0, {'method': 'none', 'details': 'No threats detected'}
    
    def _rule_based_check(self, text: str) -> Dict:
        """基于规则的检测"""
        matched_patterns = []
        
        for pattern in self.malicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matched_patterns.append(pattern)
        
        if matched_patterns:
            return {
                'is_malicious': True,
                'confidence': 1.0,
                'method': 'rule_based',
                'matched_patterns': matched_patterns,
                'details': f'Matched {len(matched_patterns)} malicious patterns'
            }
        
        return {
            'is_malicious': False,
            'confidence': 0.0,
            'method': 'rule_based',
            'details': 'No pattern matches'
        }
    
    def _ml_based_check(self, text: str) -> Dict:
        """基于ML模型的检测"""
        try:
            # 截断过长文本
            text_truncated = text[:512]
            
            # 零样本分类
            result = self.classifier(
                text_truncated,
                candidate_labels=["normal content", "malicious instruction"],
                hypothesis_template="This text contains {}."
            )
            
            # 解析结果
            labels = result['labels']
            scores = result['scores']
            
            malicious_idx = labels.index("malicious instruction")
            malicious_score = scores[malicious_idx]
            
            is_malicious = malicious_score > 0.7
            
            return {
                'is_malicious': is_malicious,
                'confidence': malicious_score,
                'method': 'ml_based',
                'details': f'ML score: {malicious_score:.3f}'
            }
        
        except Exception as e:
            return {
                'is_malicious': False,
                'confidence': 0.0,
                'method': 'ml_based',
                'error': str(e)
            }