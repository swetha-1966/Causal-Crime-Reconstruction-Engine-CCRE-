"""
Event Extractor Service
Parses raw log entries into structured Event objects.
Handles both JSON and CSV formats.
"""

import csv
import io
import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

from models.schema import Event, RawLog

logger = logging.getLogger(__name__)

# Base date for relative time parsing (today's date)
BASE_DATE = datetime.now().strftime("%Y-%m-%d")


def parse_timestamp(time_str: str) -> str:
    """
    Normalize a timestamp string into ISO format.
    Handles formats like:
      - "10:00" (HH:MM) -> today's date + time
      - "2024-01-15T10:00:00" (ISO format) -> as-is
      - "2024-01-15 10:00:00" -> converted to ISO
    """
    time_str = time_str.strip()

    # Try HH:MM format
    if len(time_str) <= 5 and ":" in time_str:
        return f"{BASE_DATE}T{time_str}:00"

    # Try HH:MM:SS format
    if len(time_str) <= 8 and time_str.count(":") == 2 and "T" not in time_str and "-" not in time_str:
        return f"{BASE_DATE}T{time_str}"

    # Try ISO format directly
    try:
        dt = datetime.fromisoformat(time_str)
        return dt.isoformat()
    except ValueError:
        pass

    # Try common datetime format
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%m/%d/%Y %H:%M:%S"]:
        try:
            dt = datetime.strptime(time_str, fmt)
            return dt.isoformat()
        except ValueError:
            continue

    # Fallback: return as-is
    logger.warning(f"Could not parse timestamp: {time_str}")
    return time_str


def extract_events_from_json(data: List[Dict[str, Any]]) -> List[Event]:
    """
    Extract structured events from JSON log entries.
    
    Input format:
        [{"event": "...", "time": "...", "user": "...", "resource": "...", ...}]
    
    Output:
        List of Event objects with normalized fields.
    """
    events = []
    for i, entry in enumerate(data):
        # Extract metadata: prefer nested 'metadata' key, fall back to non-standard top-level keys
        raw_meta = entry.get("metadata", {})
        if not isinstance(raw_meta, dict):
            raw_meta = {}
        # Also include any non-standard top-level keys
        extra_meta = {k: v for k, v in entry.items()
                      if k not in ["event", "time", "timestamp", "user", "resource", "event_type", "metadata"]}
        combined_meta = {**raw_meta, **extra_meta}

        event_id = f"evt_{i+1}_{entry.get('event', 'unknown')}"
        event = Event(
            id=event_id,
            event_type=entry.get("event", entry.get("event_type", "unknown")),
            user=entry.get("user", "unknown"),
            timestamp=parse_timestamp(entry.get("time", entry.get("timestamp", ""))),
            resource=entry.get("resource", "N/A"),
            metadata=combined_meta,
        )
        events.append(event)

    logger.info(f"Extracted {len(events)} events from JSON data.")
    return events


def extract_events_from_csv(csv_content: str) -> List[Event]:
    """
    Extract structured events from CSV log content.
    
    Expected columns: event, time, user (optional), resource (optional)
    """
    events = []
    reader = csv.DictReader(io.StringIO(csv_content))

    for i, row in enumerate(reader):
        event_id = f"evt_{i+1}_{row.get('event', 'unknown')}"
        event = Event(
            id=event_id,
            event_type=row.get("event", row.get("event_type", "unknown")),
            user=row.get("user", "unknown"),
            timestamp=parse_timestamp(row.get("time", row.get("timestamp", ""))),
            resource=row.get("resource", "N/A"),
            metadata={k: v for k, v in row.items()
                      if k not in ["event", "time", "timestamp", "user", "resource", "event_type"]}
        )
        events.append(event)

    logger.info(f"Extracted {len(events)} events from CSV data.")
    return events


def extract_events(raw_data: Any, file_type: str = "json") -> List[Event]:
    """
    Main entry point for event extraction.
    
    Args:
        raw_data: Either a list of dicts (JSON) or a string (CSV)
        file_type: "json" or "csv"
    
    Returns:
        List of structured Event objects
    """
    if file_type == "csv":
        return extract_events_from_csv(raw_data)
    else:
        if isinstance(raw_data, str):
            raw_data = json.loads(raw_data)
        return extract_events_from_json(raw_data)
