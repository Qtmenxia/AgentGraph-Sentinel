"""
日志模块

基于loguru的结构化日志系统
"""

import sys
import json
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime
from functools import lru_cache

from loguru import logger


class JSONFormatter:
    """JSON格式化器"""
    
    def __init__(self, include_extra: bool = True):
        self.include_extra = include_extra
    
    def format(self, record: Dict[str, Any]) -> str:
        """格式化日志记录为JSON"""
        log_entry = {
            "timestamp": record["time"].isoformat(),
            "level": record["level"].name,
            "message": record["message"],
            "module": record["module"],
            "function": record["function"],
            "line": record["line"],
        }
        
        # 添加额外字段
        if self.include_extra and record.get("extra"):
            for key, value in record["extra"].items():
                if key not in log_entry:
                    log_entry[key] = value
        
        # 添加异常信息
        if record["exception"]:
            log_entry["exception"] = {
                "type": record["exception"].type.__name__,
                "value": str(record["exception"].value),
                "traceback": record["exception"].traceback,
            }
        
        return json.dumps(log_entry, ensure_ascii=False, default=str) + "\n"


def setup_logger(
    level: str = "INFO",
    log_format: str = "text",
    log_file: Optional[str] = None,
    rotation: str = "10 MB",
    retention: str = "7 days",
    colorize: bool = True,
) -> None:
    """
    配置日志系统
    
    Args:
        level: 日志级别
        log_format: 日志格式 (text/json)
        log_file: 日志文件路径
        rotation: 日志轮转大小
        retention: 日志保留时间
        colorize: 是否启用颜色
    """
    # 移除默认处理器
    logger.remove()
    
    # 控制台输出格式
    if log_format == "json":
        console_format = JSONFormatter().format
    else:
        console_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{module}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        )
    
    # 添加控制台处理器
    logger.add(
        sys.stderr,
        format=console_format,
        level=level,
        colorize=colorize and log_format != "json",
        backtrace=True,
        diagnose=True,
    )
    
    # 添加文件处理器
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_format = JSONFormatter().format if log_format == "json" else (
            "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | "
            "{module}:{function}:{line} | {message}"
        )
        
        logger.add(
            log_file,
            format=file_format,
            level=level,
            rotation=rotation,
            retention=retention,
            compression="zip",
            encoding="utf-8",
        )


def get_logger(name: str = "agentshield"):
    """
    获取带有模块名的logger
    
    Args:
        name: 模块名称
    
    Returns:
        配置好的logger实例
    """
    return logger.bind(module_name=name)


class LogContext:
    """日志上下文管理器"""
    
    def __init__(self, **kwargs):
        self.context = kwargs
        self._token = None
    
    def __enter__(self):
        self._token = logger.contextualize(**self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._token:
            self._token.__exit__(exc_type, exc_val, exc_tb)


def log_execution_time(func):
    """装饰器：记录函数执行时间"""
    from functools import wraps
    import time
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000
            logger.debug(f"{func.__name__} completed in {elapsed:.2f}ms")
            return result
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"{func.__name__} failed after {elapsed:.2f}ms: {e}")
            raise
    
    return wrapper


def log_async_execution_time(func):
    """装饰器：记录异步函数执行时间"""
    from functools import wraps
    import time
    import asyncio
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            result = await func(*args, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000
            logger.debug(f"{func.__name__} completed in {elapsed:.2f}ms")
            return result
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"{func.__name__} failed after {elapsed:.2f}ms: {e}")
            raise
    
    return wrapper


# 导出
__all__ = [
    "logger",
    "setup_logger",
    "get_logger",
    "LogContext",
    "log_execution_time",
    "log_async_execution_time",
]