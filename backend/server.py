"""APIGuardian Server Entry Point - FastAPI application for Supervisor"""
import os
import sys
import logging

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv('/app/backend/.env')

# Add the backend directory to path for imports
sys.path.insert(0, '/app/backend')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import the FastAPI app from apiguardian
from apiguardian.web.api import app

# Re-export the app for uvicorn
__all__ = ['app']

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8001,
        reload=True
    )
