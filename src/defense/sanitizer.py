"""
净化器 - 清洗外部数据中的潜在恶意内容
基于Minimizer-Sanitizer思想
"""
import re
from typing import Dict, Any
from bs4 import BeautifulSoup

class Sanitizer:
    """数据净化器"""
    
    def __init__(self):
        """初始化净化器"""
        self.max_length = 2000  # 最大文本长度
        self.suspicious_tags = ['script', 'iframe', 'object', 'embed']
        
    def clean(self, data: Any, data_type: str = 'text') -> Any:
        """
        清洗数据
        
        Args:
            data: 原始数据
            data_type: 数据类型 (text, html, json)
        
        Returns:
            清洗后的数据
        """
        if data_type == 'html':
            return self._clean_html(data)
        elif data_type == 'text':
            return self._clean_text(data)
        elif data_type == 'json':
            return self._clean_json(data)
        else:
            return self._clean_text(str(data))
    
    def _clean_html(self, html: str) -> str:
        """清洗HTML内容"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # 移除危险标签
            for tag in self.suspicious_tags:
                for element in soup.find_all(tag):
                    element.decompose()
            
            # 移除隐藏内容
            for element in soup.find_all(style=re.compile(r'display\s*:\s*none', re.I)):
                element.decompose()
            
            # 提取文本
            text = soup.get_text(separator=' ', strip=True)
            
            return self._clean_text(text)
        
        except Exception as e:
            # 如果HTML解析失败，退回到文本清洗
            return self._clean_text(html)
    
    def _clean_text(self, text: str) -> str:
        """清洗文本内容"""
        if not isinstance(text, str):
            text = str(text)
        
        # 1. 移除明显的注入模式
        text = re.sub(
            r'(ignore|disregard|forget).*(previous|prior|above).*instructions',
            '[REMOVED]',
            text,
            flags=re.IGNORECASE
        )
        
        # 2. 移除系统提示符模式
        text = re.sub(
            r'(system|assistant|user)\s*:',
            '[REMOVED]',
            text,
            flags=re.IGNORECASE
        )
        
        # 3. 截断过长文本
        if len(text) > self.max_length:
            text = text[:self.max_length] + '... [TRUNCATED]'
        
        # 4. 移除多余空白
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def _clean_json(self, data: Dict) -> Dict:
        """清洗JSON数据"""
        if not isinstance(data, dict):
            return {}
        
        cleaned = {}
        for key, value in data.items():
            if isinstance(value, str):
                cleaned[key] = self._clean_text(value)
            elif isinstance(value, dict):
                cleaned[key] = self._clean_json(value)
            elif isinstance(value, list):
                cleaned[key] = [
                    self._clean_text(v) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                cleaned[key] = value
        
        return cleaned