"""
规则引擎 - 基于LLM Guard的规则检测
"""
import re
from typing import List, Dict, Any

class RuleEngine:
    """规则引擎 - 基于正则表达式和关键词的快速检测"""
    
    def __init__(self):
        """初始化规则引擎"""
        self.rules = self._load_default_rules()
    
    def _load_default_rules(self) -> List[Dict[str, Any]]:
        """加载默认规则"""
        return [
            {
                'name': 'prompt_injection',
                'pattern': r'(ignore|disregard|forget).*(previous|prior|above)',
                'severity': 'high',
                'category': 'instruction_override'
            },
            {
                'name': 'system_prompt_leak',
                'pattern': r'(repeat|show|display).*(system prompt|instructions)',
                'severity': 'high',
                'category': 'information_disclosure'
            },
            {
                'name': 'role_manipulation',
                'pattern': r'you are (now|actually|really) (a|an)',
                'severity': 'high',
                'category': 'role_manipulation'
            },
            {
                'name': 'data_exfiltration',
                'pattern': r'send.*(email|message|request).*(to|at)\s+\S+@\S+',
                'severity': 'critical',
                'category': 'data_exfiltration'
            },
            {
                'name': 'file_operation',
                'pattern': r'(write|save|create|delete).*(file|document)',
                'severity': 'high',
                'category': 'file_operation'
            }
        ]
    
    def check(self, text: str) -> Dict[str, Any]:
        """
        检查文本是否匹配规则
        
        Args:
            text: 待检测文本
        
        Returns:
            检测结果
        """
        matched_rules = []
        
        for rule in self.rules:
            if re.search(rule['pattern'], text, re.IGNORECASE):
                matched_rules.append({
                    'name': rule['name'],
                    'severity': rule['severity'],
                    'category': rule['category']
                })
        
        if matched_rules:
            # 计算最高严重程度
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            max_severity = max(
                matched_rules,
                key=lambda x: severity_order.get(x['severity'], 0)
            )['severity']
            
            return {
                'is_malicious': True,
                'matched_rules': matched_rules,
                'max_severity': max_severity,
                'rule_count': len(matched_rules)
            }
        
        return {
            'is_malicious': False,
            'matched_rules': [],
            'max_severity': None,
            'rule_count': 0
        }