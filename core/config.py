"""
Configuration management for Ghidra Headless REST API
"""
from pydantic_settings import BaseSettings
from typing import Optional
from pathlib import Path


class Settings(BaseSettings):
    """Application settings"""
    
    API_KEY: str = ""
    API_BASE: str = ""
    MODEL_NAME: str = ""
    ADMIN_USERNAME: str = ""
    ADMIN_EMAIL: str = ""
    ADMIN_PASSWORD: str = ""

    GHIDRA_HOME: str = "/opt/ghidra"
    GHIDRA_VERSION: str = "12.0.4"
    GHIDRA_BIN: str = "/opt/ghidra/support/analyzeHeadless"
    GHIDRA_SCRIPTS: str = "/app/ghidra_scripts"
   
    DATA_DIR: Path = Path("/data/ghidra_projects")
    MCP_DESCRIPTOR: Path = Path("/srv/mcp/ghidra_tool_descriptor.json")
    MCP_TOOLS: Path = Path("/srv/mcp/tools.json")
    
   
    MAX_UPLOAD_SIZE: int = 200 * 1024 * 1024  
    API_TITLE: str = "Ghidra Headless REST API"
    API_VERSION: str = "2.0.0"
    
    
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    CELERY_TASK_TIMEOUT: int = 1800  

    LOG_LEVEL: str = "INFO"
    
 
    OLLAMA_MAX_TOKENS: int = 4096
    OLLAMA_TEMPERATURE: float = 0.7
    

    LLM4DECOMPILE_MODEL_PATH: Optional[str] = "LLM4Binary/llm4decompile-1.3b-v2"
    LLM4DECOMPILE_DEVICE: str = "auto"
    LLM4DECOMPILE_DTYPE: str = "bfloat16"
    LLM4DECOMPILE_MAX_MEMORY: Optional[str] = None
    LLM4DECOMPILE_QUANTIZATION: Optional[str] = None
    LLM4DECOMPILE_MAX_NEW_TOKENS: int = 2048
    LLM4DECOMPILE_TEMPERATURE: float = 0.2
    LLM4DECOMPILE_REPETITION_PENALTY: float = 1.0
    LLM4DECOMPILE_TOP_P: float = 0.95
    LLM4DECOMPILE_TOP_K: int = 50
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
