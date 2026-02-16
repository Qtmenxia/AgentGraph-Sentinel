"""
日志工具
"""
import sys
from loguru import logger

def setup_logger():
    """配置日志"""
    logger.remove()
    
    # 控制台输出
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        level="DEBUG"
    )
    
    # 文件输出
    logger.add(
        "logs/ags_{time}.log",
        rotation="500 MB",
        retention="10 days",
        level="DEBUG"
    )
    
    return logger

# 全局logger实例
log = setup_logger()