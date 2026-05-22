"""
Upload Route
Handles file upload of JSON/CSV log files.
"""

import json
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException

from services.event_extractor import extract_events
from models.schema import UploadResponse

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory storage for the current session
uploaded_events = []
raw_data = []
ground_truth_edges = None


@router.post("/upload", response_model=UploadResponse)
async def upload_logs(file: UploadFile = File(...)):
    """
    Upload log file (JSON or CSV) for analysis.
    
    Accepts:
      - .json files: array of log objects
      - .csv files: CSV with event, time, user, resource columns
    
    Returns:
      - Parsed event count and extracted events
    """
    global uploaded_events, raw_data, ground_truth_edges

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    # Determine file type
    filename = file.filename.lower()
    if filename.endswith(".json"):
        file_type = "json"
    elif filename.endswith(".csv"):
        file_type = "csv"
    else:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Please upload .json or .csv files."
        )

    try:
        content = await file.read()
        content_str = content.decode("utf-8")

        if file_type == "json":
            raw_data = json.loads(content_str)
            if isinstance(raw_data, dict) and "logs" in raw_data:
                events = extract_events(raw_data["logs"], file_type="json")
                ground_truth_edges = raw_data.get("ground_truth_edges")
            else:
                events = extract_events(raw_data, file_type="json")
                ground_truth_edges = None
        else:
            raw_data = content_str
            events = extract_events(content_str, file_type="csv")
            ground_truth_edges = None

        uploaded_events = events
        logger.info(f"Uploaded {len(events)} events from {file.filename}")

        return UploadResponse(
            message=f"Successfully parsed {len(events)} events from {file.filename}",
            event_count=len(events),
            events=events
        )

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format.")
    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")


def get_uploaded_events():
    """Get the currently uploaded events."""
    return uploaded_events


def get_raw_data():
    """Get the raw uploaded data."""
    return raw_data

def get_ground_truth_edges():
    """Get the ground truth edges if uploaded."""
    return ground_truth_edges

