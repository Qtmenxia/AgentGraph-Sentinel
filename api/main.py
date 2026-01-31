import os

# === 强行禁用 LangSmith ===
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGCHAIN_API_KEY"] = ""
os.environ["LANGCHAIN_PROJECT"] = ""
# ==========================
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config.settings import get_settings
from api.routers import detection, visualization
from src.utils.logger import setup_logger

settings = get_settings()
logger = setup_logger()

app = FastAPI(
    title=settings.APP_NAME,
    description="2026 CISCN Competition Entry - AgentGraph Sentinel",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For demo purposes
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(detection.router)
app.include_router(visualization.router)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "model_provider": "OpenRouter" if settings.OPENROUTER_API_KEY else "Local/Other"
    }

@app.on_event("startup")
async def startup_event():
    logger.info("Starting AgentGraph Sentinel...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT)
