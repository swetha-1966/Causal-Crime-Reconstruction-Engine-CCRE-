"""
CCRE Backend — Main Application
AI Causal Crime Reconstruction Engine

FastAPI server with routes for:
  - /upload  — Upload log files
  - /process — Run analysis pipeline
  - /graph   — Retrieve graph data
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes import upload, process
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="CCRE — Causal Crime Reconstruction Engine",
    description=(
        "AI-powered system that reconstructs cyber incidents "
        "as causal graphs and timelines from raw logs."
    ),
    version="2.0.0",
)

# CORS middleware — allow frontend connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(upload.router, tags=["Upload"])
app.include_router(process.router, tags=["Process"])


@app.get("/")
async def root():
    """Health check / welcome endpoint."""
    return {
        "service": "CCRE — Causal Crime Reconstruction Engine",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "upload": "POST /upload",
            "process": "POST /process",
            "graph": "GET /graph",
            "results": "GET /results",
            "report": "GET /report",
        }
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}
