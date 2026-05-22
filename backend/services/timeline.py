"""
Timeline Builder Service
Sorts events chronologically and assigns sequence numbers.
"""

import logging
from typing import List
from datetime import datetime

from models.schema import Event

logger = logging.getLogger(__name__)


def build_timeline(events: List[Event]) -> List[Event]:
    """
    Sort events by timestamp and assign sequence numbers.
    
    Args:
        events: List of unsorted Event objects
    
    Returns:
        Chronologically ordered list of Events with sequence numbers
    """
    def parse_time(ts: str) -> datetime:
        """Parse timestamp string for sorting."""
        try:
            return datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            # Fallback for non-standard formats
            return datetime.min

    # Sort by timestamp
    sorted_events = sorted(events, key=lambda e: parse_time(e.timestamp))

    # Assign sequence numbers
    for i, event in enumerate(sorted_events):
        event.sequence = i + 1

    logger.info(f"Built timeline with {len(sorted_events)} events.")
    return sorted_events
