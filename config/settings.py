import os
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # App Config
    APP_NAME: str = "AgentGraph Sentinel"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = True
    
    # LLM Config (OpenRouter / OpenAI / Anthropic)
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "openai/gpt-3.5-turbo" # Default cheap model
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    
    # Fallback Keys
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    
    # Detection Thresholds
    GRAPH_ANOMALY_THRESHOLD: float = 0.3
    NODE_RISK_THRESHOLD: float = 0.7
    
    # Paths
    LOG_DIR: str = "logs"
    DATA_DIR: str = "data"

    class Config:
        env_file = ".env"
        extra = "ignore"

@lru_cache()
def get_settings():
    return Settings()
