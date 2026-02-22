"""
规则引擎 - 基于LLM Guard的规则检测（Firewall增强版）

核心特性：
1. 双防火墙架构：输入防火墙（Minimizer） + 输出防火墙（Sanitizer）
2. 工具感知安全策略：针对不同工具类型应用不同的安全规则
3. 上下文感知过滤：结合用户原始任务和工具上下文进行智能过滤
4. 多层防御机制：正则规则 + 语义分析 + LLM辅助决策
5. 动态规则配置：支持JSON配置文件和运行时规则更新
6. 完整的审计日志：记录所有过滤和检测操作
7. 性能优化：缓存机制和批量处理支持

论文核心思想映射：
- Minimizer (输入防火墙) -> 参数净化和最小化
- Sanitizer (输出防火墙) -> 工具输出内容净化
- 工具描述感知 -> 工具特定的安全策略
- 用户任务上下文 -> 结合原始任务进行安全决策
"""

import re
import json
import logging
import hashlib
from typing import List, Dict, Any, Callable, Optional, Union, Tuple
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import threading
from functools import lru_cache
import asyncio
from concurrent.futures import ThreadPoolExecutor

# ==================== 基础枚举和数据结构 ====================

class Severity(Enum):
    """严重程度枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Category(Enum):
    """威胁类别枚举"""
    INSTRUCTION_OVERRIDE = "instruction_override"
    INFORMATION_DISCLOSURE = "information_disclosure"
    ROLE_MANIPULATION = "role_manipulation"
    DATA_EXFILTRATION = "data_exfiltration"
    FILE_OPERATION = "file_operation"
    COMMAND_EXECUTION = "command_execution"
    PRIVACY_VIOLATION = "privacy_violation"
    SYSTEM_COMPROMISE = "system_compromise"
    CONTEXT_HIJACKING = "context_hijacking"
    TOOL_MISUSE = "tool_misuse"

@dataclass
class DetectionResult:
    """检测结果数据类"""
    is_malicious: bool
    matched_rules: List[Dict[str, Any]]
    max_severity: Optional[str]
    rule_count: int
    confidence_scores: Dict[str, float]
    filtered_content: Optional[str] = None
    original_length: Optional[int] = None
    filtered_length: Optional[int] = None

@dataclass
class FirewallContext:
    """防火墙上下文信息"""
    user_task: str
    tool_name: str
    tool_description: str
    tool_args: Optional[Dict[str, Any]] = None
    original_content: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    session_id: Optional[str] = None

@dataclass
class AuditLog:
    """审计日志条目"""
    firewall_type: str  # "input" or "output"
    operation: str      # "filter", "sanitize", "detect"
    context: FirewallContext
    result: DetectionResult
    processing_time: float
    rule_applied: Optional[str] = None

# ==================== 规则基类和实现 ====================

class Rule(ABC):
    """规则抽象基类"""
    
    def __init__(self, name: str, severity: Severity, category: Category, 
                 description: str = "", enabled: bool = True, 
                 tool_scope: Optional[List[str]] = None):
        self.name = name
        self.severity = severity
        self.category = category
        self.description = description
        self.enabled = enabled
        self.tool_scope = tool_scope  # None表示适用于所有工具
    
    @abstractmethod
    def match(self, text: str, context: Optional[FirewallContext] = None) -> bool:
        """检查文本是否匹配此规则"""
        pass
    
    @abstractmethod
    def get_confidence(self, text: str, context: Optional[FirewallContext] = None) -> float:
        """获取匹配置信度（0-1）"""
        pass
    
    @abstractmethod
    def apply_filter(self, text: str, context: Optional[FirewallContext] = None) -> str:
        """应用过滤规则，返回净化后的内容"""
        pass

class RegexRule(Rule):
    """正则表达式规则"""
    
    def __init__(self, name: str, pattern: str, severity: Severity, category: Category, 
                 description: str = "", case_sensitive: bool = False, 
                 replacement: str = "", enabled: bool = True, 
                 tool_scope: Optional[List[str]] = None):
        super().__init__(name, severity, category, description, enabled, tool_scope)
        self.pattern = pattern
        self.replacement = replacement
        self.flags = 0 if case_sensitive else re.IGNORECASE
        try:
            self.compiled_pattern = re.compile(pattern, self.flags)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
    
    def match(self, text: str, context: Optional[FirewallContext] = None) -> bool:
        if not self.enabled:
            return False
        if self.tool_scope and context and context.tool_name not in self.tool_scope:
            return False
        return bool(self.compiled_pattern.search(text))
    
    def get_confidence(self, text: str, context: Optional[FirewallContext] = None) -> float:
        if not self.match(text, context):
            return 0.0
        matches = len(self.compiled_pattern.findall(text))
        return min(matches * 0.3, 0.9)
    
    def apply_filter(self, text: str, context: Optional[FirewallContext] = None) -> str:
        if not self.match(text, context):
            return text
        return self.compiled_pattern.sub(self.replacement, text)

class KeywordRule(Rule):
    """关键词规则"""
    
    def __init__(self, name: str, keywords: List[str], severity: Severity, category: Category,
                 description: str = "", case_sensitive: bool = False, 
                 replacement_strategy: str = "remove", enabled: bool = True,
                 tool_scope: Optional[List[str]] = None):
        super().__init__(name, severity, category, description, enabled, tool_scope)
        self.keywords = keywords if case_sensitive else [k.lower() for k in keywords]
        self.case_sensitive = case_sensitive
        self.replacement_strategy = replacement_strategy  # "remove", "mask", "replace"
    
    def match(self, text: str, context: Optional[FirewallContext] = None) -> bool:
        if not self.enabled:
            return False
        if self.tool_scope and context and context.tool_name not in self.tool_scope:
            return False
        search_text = text if self.case_sensitive else text.lower()
        return any(keyword in search_text for keyword in self.keywords)
    
    def get_confidence(self, text: str, context: Optional[FirewallContext] = None) -> float:
        if not self.match(text, context):
            return 0.0
        search_text = text if self.case_sensitive else text.lower()
        matches = sum(1 for keyword in self.keywords if keyword in search_text)
        return min(matches * 0.3, 0.9)
    
    def apply_filter(self, text: str, context: Optional[FirewallContext] = None) -> str:
        if not self.match(text, context):
            return text
        
        result = text
        if self.case_sensitive:
            for keyword in self.keywords:
                if self.replacement_strategy == "remove":
                    result = result.replace(keyword, "")
                elif self.replacement_strategy == "mask":
                    result = result.replace(keyword, "*" * len(keyword))
                elif self.replacement_strategy == "replace":
                    result = result.replace(keyword, "[FILTERED]")
        else:
            # 非大小写敏感的替换需要更复杂的处理以保持原文大小写
            for keyword in self.keywords:
                result = re.sub(
                    re.escape(keyword), 
                    self._get_replacement(keyword, self.replacement_strategy),
                    result, 
                    flags=re.IGNORECASE
                )
        return result
    
    def _get_replacement(self, original: str, strategy: str) -> str:
        """获取替换字符串"""
        if strategy == "remove":
            return ""
        elif strategy == "mask":
            return "*" * len(original)
        elif strategy == "replace":
            return "[FILTERED]"
        return ""

class SemanticRule(Rule):
    """语义分析规则（高级模式匹配）"""
    
    def __init__(self, name: str, patterns: List[Dict[str, Any]], severity: Severity, 
                 category: Category, description: str = "", enabled: bool = True,
                 tool_scope: Optional[List[str]] = None):
        super().__init__(name, severity, category, description, enabled, tool_scope)
        self.patterns = patterns
    
    def match(self, text: str, context: Optional[FirewallContext] = None) -> bool:
        if not self.enabled:
            return False
        if self.tool_scope and context and context.tool_name not in self.tool_scope:
            return False
        
        text_lower = text.lower()
        
        for pattern in self.patterns:
            # 检查必须包含的关键词
            required_keywords = pattern.get("required", [])
            if not all(kw in text_lower for kw in required_keywords):
                continue
            
            # 检查禁止的关键词
            forbidden_keywords = pattern.get("forbidden", [])
            if any(kw in text_lower for kw in forbidden_keywords):
                continue
            
            # 检查上下文关键词（可选）
            context_keywords = pattern.get("context", [])
            if context_keywords and not any(kw in text_lower for kw in context_keywords):
                continue
            
            return True
        
        return False
    
    def get_confidence(self, text: str, context: Optional[FirewallContext] = None) -> float:
        if not self.match(text, context):
            return 0.0
        
        text_lower = text.lower()
        score = 0.0
        
        for pattern in self.patterns:
            required_keywords = pattern.get("required", [])
            matches = sum(1 for kw in required_keywords if kw in text_lower)
            if matches == len(required_keywords):
                # 计算上下文匹配度
                context_keywords = pattern.get("context", [])
                context_matches = sum(1 for kw in context_keywords if kw in text_lower)
                context_score = context_matches / max(len(context_keywords), 1) if context_keywords else 1.0
                
                pattern_score = 0.5 + (context_score * 0.4)  # 基础分0.5 + 上下文分
                score = max(score, pattern_score)
        
        return min(score, 0.95)
    
    def apply_filter(self, text: str, context: Optional[FirewallContext] = None) -> str:
        if not self.match(text, context):
            return text
        
        # 对于语义规则，我们采用更保守的策略：移除整个可疑段落
        # 在实际应用中，这里可以集成更复杂的NLP模型来进行精确过滤
        return "[SEMANTIC_CONTENT_FILTERED]"

class ContextualRule(Rule):
    """上下文感知规则"""
    
    def __init__(self, name: str, severity: Severity, category: Category,
                 condition_func: Callable[[str, Optional[FirewallContext]], bool],
                 filter_func: Callable[[str, Optional[FirewallContext]], str],
                 confidence_func: Callable[[str, Optional[FirewallContext]], float],
                 description: str = "", enabled: bool = True,
                 tool_scope: Optional[List[str]] = None):
        super().__init__(name, severity, category, description, enabled, tool_scope)
        self.condition_func = condition_func
        self.filter_func = filter_func
        self.confidence_func = confidence_func
    
    def match(self, text: str, context: Optional[FirewallContext] = None) -> bool:
        if not self.enabled:
            return False
        if self.tool_scope and context and context.tool_name not in self.tool_scope:
            return False
        return self.condition_func(text, context)
    
    def get_confidence(self, text: str, context: Optional[FirewallContext] = None) -> float:
        if not self.match(text, context):
            return 0.0
        return self.confidence_func(text, context)
    
    def apply_filter(self, text: str, context: Optional[FirewallContext] = None) -> str:
        if not self.match(text, context):
            return text
        return self.filter_func(text, context)

# ==================== 防火墙核心类 ====================

class FirewallBase(ABC):
    """防火墙基类"""
    
    def __init__(self, name: str, enable_logging: bool = True, 
                 cache_size: int = 1000, max_workers: int = 4):
        self.name = name
        self.rules: List[Rule] = []
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.audit_logs: List[AuditLog] = []
        self.cache_size = cache_size
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        if enable_logging:
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
                self.logger.setLevel(logging.INFO)
    
    @abstractmethod
    def process(self, content: str, context: FirewallContext) -> DetectionResult:
        """处理内容并返回检测结果"""
        pass
    
    def add_rule(self, rule: Rule):
        """添加规则"""
        self.rules.append(rule)
        self.logger.info(f"Added rule: {rule.name}")
    
    def remove_rule(self, rule_name: str):
        """移除规则"""
        self.rules = [rule for rule in self.rules if rule.name != rule_name]
        self.logger.info(f"Removed rule: {rule_name}")
    
    def clear_rules(self):
        """清空所有规则"""
        self.rules.clear()
        self.logger.info("Cleared all rules")
    
    def _log_audit(self, firewall_type: str, operation: str, 
                   context: FirewallContext, result: DetectionResult, 
                   processing_time: float, rule_applied: Optional[str] = None):
        """记录审计日志"""
        audit_entry = AuditLog(
            firewall_type=firewall_type,
            operation=operation,
            context=context,
            result=result,
            processing_time=processing_time,
            rule_applied=rule_applied
        )
        self.audit_logs.append(audit_entry)
    
    def get_audit_logs(self) -> List[AuditLog]:
        """获取审计日志"""
        return self.audit_logs.copy()
    
    def clear_audit_logs(self):
        """清空审计日志"""
        self.audit_logs.clear()

class InputFirewall(FirewallBase):
    """输入防火墙（Minimizer）- 负责参数净化和最小化"""
    
    def __init__(self, **kwargs):
        super().__init__("InputFirewall", **kwargs)
        self._load_default_rules()
    
    def _load_default_rules(self):
        """加载默认输入防火墙规则"""
        # 敏感信息过滤规则
        self.add_rule(RegexRule(
            name="pii_removal",
            pattern=r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',  # SSN格式
            severity=Severity.HIGH,
            category=Category.PRIVACY_VIOLATION,
            description="移除社会安全号码",
            replacement="[SSN_REMOVED]"
        ))
        
        self.add_rule(RegexRule(
            name="email_removal",
            pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            severity=Severity.MEDIUM,
            category=Category.DATA_EXFILTRATION,
            description="移除邮箱地址",
            replacement="[EMAIL_REMOVED]"
        ))
        
        self.add_rule(RegexRule(
            name="phone_removal",
            pattern=r'\b\d{3}-\d{3}-\d{4}\b|\(\d{3}\)\s*\d{3}-\d{4}',
            severity=Severity.MEDIUM,
            category=Category.PRIVACY_VIOLATION,
            description="移除电话号码",
            replacement="[PHONE_REMOVED]"
        ))
        
        # 指令覆盖防护
        self.add_rule(RegexRule(
            name="instruction_override_input",
            pattern=r'(ignore|disregard|forget|override).*(previous|prior|above|instructions)',
            severity=Severity.HIGH,
            category=Category.INSTRUCTION_OVERRIDE,
            description="防止指令覆盖攻击（输入端）",
            replacement=""
        ))
        
        # 工具特定规则 - 文件操作
        self.add_rule(KeywordRule(
            name="file_path_sanitization",
            keywords=["..\\", "../", "/etc/", "C:\\", "D:\\"],
            severity=Severity.HIGH,
            category=Category.FILE_OPERATION,
            description="路径遍历防护",
            replacement_strategy="remove",
            tool_scope=["read_file", "write_file", "delete_file"]
        ))
        
        # 工具特定规则 - 数据库查询
        self.add_rule(KeywordRule(
            name="sql_injection_prevention",
            keywords=["';", "--", "/*", "xp_cmdshell", "UNION SELECT"],
            severity=Severity.CRITICAL,
            category=Category.SYSTEM_COMPROMISE,
            description="SQL注入防护",
            replacement_strategy="remove",
            tool_scope=["query_database", "execute_sql"]
        ))
        
        # 上下文感知规则 - 基于用户任务的参数验证
        def task_aware_validation(text: str, context: Optional[FirewallContext]) -> bool:
            if not context or not context.user_task:
                return False
            # 简单示例：如果用户任务是发送邮件，但参数包含文件操作指令
            user_task_lower = context.user_task.lower()
            text_lower = text.lower()
            
            if "email" in user_task_lower or "send" in user_task_lower:
                dangerous_patterns = ["delete", "remove", "format", "destroy"]
                return any(pattern in text_lower for pattern in dangerous_patterns)
            return False
        
        def task_aware_filter(text: str, context: Optional[FirewallContext]) -> str:
            # 移除与用户任务不符的危险操作
            dangerous_patterns = ["delete", "remove", "format", "destroy"]
            for pattern in dangerous_patterns:
                text = text.replace(pattern, "[TASK_INCONSISTENT]")
            return text
        
        def task_aware_confidence(text: str, context: Optional[FirewallContext]) -> float:
            return 0.8 if task_aware_validation(text, context) else 0.0
        
        self.add_rule(ContextualRule(
            name="task_consistency_check",
            severity=Severity.HIGH,
            category=Category.CONTEXT_HIJACKING,
            condition_func=task_aware_validation,
            filter_func=task_aware_filter,
            confidence_func=task_aware_confidence,
            description="检查参数与用户任务的一致性"
        ))
    
    def minimize_arguments(self, args: Dict[str, Any], context: FirewallContext) -> Dict[str, Any]:
        """
        最小化工具参数，只保留完成用户任务所必需的信息
        
        Args:
            args: 原始工具参数
            context: 防火墙上下文
            
        Returns:
            最小化后的参数
        """
        minimized_args = {}
        reasoning = []
        
        # 分析每个参数
        for key, value in args.items():
            if value is None:
                minimized_args[key] = value
                continue
            
            # 将参数值转换为字符串进行处理
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value)
            else:
                value_str = str(value)
            
            # 应用防火墙规则
            result = self.process(value_str, context)
            
            if result.is_malicious:
                # 如果检测到恶意内容，根据严重程度决定如何处理
                if result.max_severity in ['critical', 'high']:
                    # 高危内容直接移除或替换为安全值
                    minimized_args[key] = "[SANITIZED]"
                    reasoning.append(f"Parameter '{key}' contained malicious content and was sanitized")
                else:
                    # 中低危内容尝试净化后保留
                    if result.filtered_content:
                        try:
                            # 尝试恢复原始数据类型
                            if isinstance(value, (dict, list)):
                                minimized_args[key] = json.loads(result.filtered_content)
                            else:
                                minimized_args[key] = result.filtered_content
                        except:
                            minimized_args[key] = result.filtered_content
                        reasoning.append(f"Parameter '{key}' was sanitized to remove malicious content")
                    else:
                        minimized_args[key] = value
            else:
                # 无恶意内容，直接保留
                minimized_args[key] = value
        
        # 记录最小化推理过程
        context.reasoning = reasoning
        return minimized_args
    
    def process(self, content: str, context: FirewallContext) -> DetectionResult:
        """处理输入内容"""
        start_time = datetime.now().timestamp()
        matched_rules = []
        confidence_scores = {}
        filtered_content = content
        
        # 应用所有规则
        for rule in self.rules:
            if rule.match(content, context):
                matched_rules.append({
                    'name': rule.name,
                    'severity': rule.severity.value,
                    'category': rule.category.value,
                    'description': rule.description
                })
                confidence_scores[rule.name] = rule.get_confidence(content, context)
                # 应用过滤
                filtered_content = rule.apply_filter(filtered_content, context)
        
        # 构建结果
        if matched_rules:
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            max_severity = max(
                matched_rules,
                key=lambda x: severity_order.get(x['severity'], 0)
            )['severity']
            
            result = DetectionResult(
                is_malicious=True,
                matched_rules=matched_rules,
                max_severity=max_severity,
                rule_count=len(matched_rules),
                confidence_scores=confidence_scores,
                filtered_content=filtered_content,
                original_length=len(content),
                filtered_length=len(filtered_content)
            )
        else:
            result = DetectionResult(
                is_malicious=False,
                matched_rules=[],
                max_severity=None,
                rule_count=0,
                confidence_scores={},
                filtered_content=content,
                original_length=len(content),
                filtered_length=len(content)
            )
        
        # 记录审计日志
        processing_time = datetime.now().timestamp() - start_time
        self._log_audit(
            firewall_type="input",
            operation="filter",
            context=context,
            result=result,
            processing_time=processing_time
        )
        
        return result

class OutputFirewall(FirewallBase):
    """输出防火墙（Sanitizer）- 负责工具输出内容净化"""
    
    def __init__(self, **kwargs):
        super().__init__("OutputFirewall", **kwargs)
        self._load_default_rules()
    
    def _load_default_rules(self):
        """加载默认输出防火墙规则"""
        # 指令注入防护
        self.add_rule(SemanticRule(
            name="prompt_injection_detection",
            patterns=[
                {
                    "required": ["ignore", "previous", "instructions"],
                    "context": ["all", "everything", "above", "prior"]
                },
                {
                    "required": ["you", "are", "now"],
                    "context": ["hacker", "attacker", "malicious", "evil"]
                },
                {
                    "required": ["forget", "everything"],
                    "context": ["i", "told", "you"]
                }
            ],
            severity=Severity.CRITICAL,
            category=Category.INSTRUCTION_OVERRIDE,
            description="检测提示注入攻击"
        ))
        
        # 系统信息泄露防护
        self.add_rule(RegexRule(
            name="system_info_leak",
            pattern=r'(system\s+prompt|internal\s+instructions|api\s+key|secret\s+key)',
            severity=Severity.CRITICAL,
            category=Category.INFORMATION_DISCLOSURE,
            description="防止系统信息泄露",
            replacement="[SYSTEM_INFO_FILTERED]"
        ))
        
        # 数据外泄防护
        self.add_rule(SemanticRule(
            name="data_exfiltration_prevention",
            patterns=[
                {
                    "required": ["send", "email", "message"],
                    "context": ["@", "gmail", "hotmail", "yahoo"]
                },
                {
                    "required": ["upload", "post", "share"],
                    "context": ["http", "https", "ftp", "webhook"]
                }
            ],
            severity=Severity.CRITICAL,
            category=Category.DATA_EXFILTRATION,
            description="防止数据外泄"
        ))
        
        # 角色扮演攻击防护
        self.add_rule(RegexRule(
            name="role_playing_attack",
            pattern=r'you\s+(are|should\s+be|must\s+act\s+as)\s+(a|an)\s+\w+',
            severity=Severity.HIGH,
            category=Category.ROLE_MANIPULATION,
            description="防止角色扮演攻击",
            replacement="You are a helpful AI assistant."
        ))
        
        # 工具特定规则 - Web搜索结果
        def web_search_sanitize(text: str, context: Optional[FirewallContext]) -> str:
            """Web搜索结果专用净化函数"""
            if not context or context.tool_name != "web_search":
                return text
            
            # 移除HTML标签和脚本
            text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r'<[^>]+>', '', text)  # 移除所有HTML标签
            
            # 移除可疑的JavaScript代码
            text = re.sub(r'javascript:\s*[^;\n]*', '[JS_FILTERED]', text, flags=re.IGNORECASE)
            
            return text
        
        def web_search_condition(text: str, context: Optional[FirewallContext]) -> bool:
            return context and context.tool_name == "web_search" and ("<script" in text.lower() or "javascript:" in text.lower())
        
        def web_search_confidence(text: str, context: Optional[FirewallContext]) -> float:
            return 0.9 if web_search_condition(text, context) else 0.0
        
        self.add_rule(ContextualRule(
            name="web_content_sanitization",
            severity=Severity.HIGH,
            category=Category.SYSTEM_COMPROMISE,
            condition_func=web_search_condition,
            filter_func=web_search_sanitize,
            confidence_func=web_search_confidence,
            description="Web搜索内容净化",
            tool_scope=["web_search"]
        ))
        
        # 工具特定规则 - 数据库查询结果
        self.add_rule(KeywordRule(
            name="database_privilege_escalation",
            keywords=["GRANT", "REVOKE", "CREATE USER", "DROP USER", "ALTER USER"],
            severity=Severity.CRITICAL,
            category=Category.SYSTEM_COMPROMISE,
            description="数据库权限提升防护",
            replacement_strategy="remove",
            tool_scope=["query_database", "execute_sql"]
        ))
        
        # 上下文感知规则 - 基于原始用户任务的输出验证
        def output_task_consistency(text: str, context: Optional[FirewallContext]) -> bool:
            if not context or not context.user_task:
                return False
            
            user_task_lower = context.user_task.lower()
            text_lower = text.lower()
            
            # 如果用户任务是获取信息，但输出包含执行指令
            if any(keyword in user_task_lower for keyword in ["get", "find", "search", "lookup"]):
                execution_keywords = ["execute", "run", "perform", "do", "make"]
                return any(exec_kw in text_lower for exec_kw in execution_keywords)
            
            return False
        
        def output_task_filter(text: str, context: Optional[FirewallContext]) -> str:
            # 移除与只读任务不符的执行指令
            execution_keywords = ["execute", "run", "perform", "do", "make"]
            for keyword in execution_keywords:
                text = re.sub(rf'\b{keyword}\b', '[READ_ONLY_TASK]', text, flags=re.IGNORECASE)
            return text
        
        def output_task_confidence(text: str, context: Optional[FirewallContext]) -> float:
            return 0.7 if output_task_consistency(text, context) else 0.0
        
        self.add_rule(ContextualRule(
            name="output_task_consistency",
            severity=Severity.MEDIUM,
            category=Category.CONTEXT_HIJACKING,
            condition_func=output_task_consistency,
            filter_func=output_task_filter,
            confidence_func=output_task_confidence,
            description="确保输出与用户任务类型一致"
        ))
    
    def process(self, content: str, context: FirewallContext) -> DetectionResult:
        """处理输出内容"""
        start_time = datetime.now().timestamp()
        matched_rules = []
        confidence_scores = {}
        filtered_content = content
        
        # 应用所有规则
        for rule in self.rules:
            if rule.match(content, context):
                matched_rules.append({
                    'name': rule.name,
                    'severity': rule.severity.value,
                    'category': rule.category.value,
                    'description': rule.description
                })
                confidence_scores[rule.name] = rule.get_confidence(content, context)
                # 应用过滤
                filtered_content = rule.apply_filter(filtered_content, context)
        
        # 构建结果
        if matched_rules:
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            max_severity = max(
                matched_rules,
                key=lambda x: severity_order.get(x['severity'], 0)
            )['severity']
            
            result = DetectionResult(
                is_malicious=True,
                matched_rules=matched_rules,
                max_severity=max_severity,
                rule_count=len(matched_rules),
                confidence_scores=confidence_scores,
                filtered_content=filtered_content,
                original_length=len(content),
                filtered_length=len(filtered_content)
            )
        else:
            result = DetectionResult(
                is_malicious=False,
                matched_rules=[],
                max_severity=None,
                rule_count=0,
                confidence_scores={},
                filtered_content=content,
                original_length=len(content),
                filtered_length=len(content)
            )
        
        # 记录审计日志
        processing_time = datetime.now().timestamp() - start_time
        self._log_audit(
            firewall_type="output",
            operation="sanitize",
            context=context,
            result=result,
            processing_time=processing_time
        )
        
        return result

# ==================== 主防火墙引擎 ====================

class FirewallEngine:
    """主防火墙引擎 - 集成输入和输出防火墙"""
    
    def __init__(self, config_file: Optional[str] = None, enable_logging: bool = True):
        """
        初始化防火墙引擎
        
        Args:
            config_file: 配置文件路径（JSON格式）
            enable_logging: 是否启用日志
        """
        self.input_firewall = InputFirewall(enable_logging=enable_logging)
        self.output_firewall = OutputFirewall(enable_logging=enable_logging)
        self.session_counter = 0
        self.lock = threading.Lock()
        
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file: str):
        """从配置文件加载规则"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 加载输入防火墙配置
            if 'input_firewall' in config:
                self._load_firewall_config(self.input_firewall, config['input_firewall'])
            
            # 加载输出防火墙配置
            if 'output_firewall' in config:
                self._load_firewall_config(self.output_firewall, config['output_firewall'])
                
        except Exception as e:
            logging.error(f"Failed to load config file {config_file}: {e}")
    
    def _load_firewall_config(self, firewall: FirewallBase, config: Dict[str, Any]):
        """加载防火墙配置"""
        if 'rules' in config:
            for rule_config in config['rules']:
                try:
                    rule = self._create_rule_from_config(rule_config)
                    firewall.add_rule(rule)
                except Exception as e:
                    logging.error(f"Failed to create rule from config: {e}")
    
    def _create_rule_from_config(self, config: Dict[str, Any]) -> Rule:
        """从配置创建规则"""
        rule_type = config.get('type', 'regex')
        severity = Severity(config.get('severity', 'medium'))
        category = Category(config.get('category', 'instruction_override'))
        
        if rule_type == 'regex':
            return RegexRule(
                name=config['name'],
                pattern=config['pattern'],
                severity=severity,
                category=category,
                description=config.get('description', ''),
                replacement=config.get('replacement', ''),
                enabled=config.get('enabled', True),
                tool_scope=config.get('tool_scope')
            )
        elif rule_type == 'keyword':
            return KeywordRule(
                name=config['name'],
                keywords=config['keywords'],
                severity=severity,
                category=category,
                description=config.get('description', ''),
                replacement_strategy=config.get('replacement_strategy', 'remove'),
                enabled=config.get('enabled', True),
                tool_scope=config.get('tool_scope')
            )
        elif rule_type == 'semantic':
            return SemanticRule(
                name=config['name'],
                patterns=config['patterns'],
                severity=severity,
                category=category,
                description=config.get('description', ''),
                enabled=config.get('enabled', True),
                tool_scope=config.get('tool_scope')
            )
        else:
            raise ValueError(f"Unsupported rule type: {rule_type}")
    
    def minimize_tool_input(self, tool_args: Dict[str, Any], 
                          user_task: str, tool_name: str, 
                          tool_description: str) -> Tuple[Dict[str, Any], DetectionResult]:
        """
        最小化工具输入参数
        
        Args:
            tool_args: 原始工具参数
            user_task: 用户原始任务
            tool_name: 工具名称
            tool_description: 工具描述
            
        Returns:
            最小化后的参数和检测结果
        """
        context = FirewallContext(
            user_task=user_task,
            tool_name=tool_name,
            tool_description=tool_description,
            tool_args=tool_args,
            session_id=self._generate_session_id()
        )
        
        minimized_args = self.input_firewall.minimize_arguments(tool_args, context)
        
        # 创建一个综合的检测结果
        all_logs = self.input_firewall.get_audit_logs()
        if all_logs:
            latest_log = all_logs[-1]
            detection_result = latest_log.result
        else:
            detection_result = DetectionResult(
                is_malicious=False,
                matched_rules=[],
                max_severity=None,
                rule_count=0,
                confidence_scores={}
            )
        
        return minimized_args, detection_result
    
    def sanitize_tool_output(self, tool_output: str,
                           user_task: str, tool_name: str,
                           tool_args: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        净化工具输出内容
        
        Args:
            tool_output: 工具原始输出
            user_task: 用户原始任务
            tool_name: 工具名称
            tool_args: 工具参数（可选）
            
        Returns:
            净化后的检测结果
        """
        context = FirewallContext(
            user_task=user_task,
            tool_name=tool_name,
            tool_description="",  # 输出防火墙通常不需要工具描述
            tool_args=tool_args,
            original_content=tool_output,
            session_id=self._generate_session_id()
        )
        
        return self.output_firewall.process(tool_output, context)
    
    def _generate_session_id(self) -> str:
        """生成会话ID"""
        with self.lock:
            self.session_counter += 1
            return f"session_{self.session_counter}_{int(datetime.now().timestamp())}"
    
    def get_audit_logs(self) -> Dict[str, List[AuditLog]]:
        """获取所有审计日志"""
        return {
            'input_firewall': self.input_firewall.get_audit_logs(),
            'output_firewall': self.output_firewall.get_audit_logs()
        }
    
    def export_rules(self) -> Dict[str, str]:
        """导出所有规则配置"""
        return {
            'input_firewall': self.input_firewall.export_rules() if hasattr(self.input_firewall, 'export_rules') else "",
            'output_firewall': self.output_firewall.export_rules() if hasattr(self.output_firewall, 'export_rules') else ""
        }
    
    def add_custom_rule(self, firewall_type: str, rule: Rule):
        """添加自定义规则"""
        if firewall_type == 'input':
            self.input_firewall.add_rule(rule)
        elif firewall_type == 'output':
            self.output_firewall.add_rule(rule)
        else:
            raise Val