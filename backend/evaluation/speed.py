"""
Evaluation Module: Investigation Speed
Calculates efficiency improvement over manual investigation.
"""
import time
import logging

logger = logging.getLogger(__name__)

def measure_system_time(start_time: float, end_time: float) -> float:
    """Measure the actual time taken by the system pipeline."""
    return max(end_time - start_time, 0.001)  # avoid division by zero

def compute_speed_improvement(manual_time: float, system_time: float) -> dict:
    """
    Compute the speed improvement ratio and time saved.
    manual_time: estimated time without system (seconds)
    system_time: time taken by pipeline (seconds)
    """
    improvement_ratio = manual_time / system_time
    time_saved = manual_time - system_time
    
    logger.info("Speed improvement measured")
    return {
        "system_time": round(system_time, 4),
        "manual_time": manual_time,
        "improvement_ratio": round(improvement_ratio, 2),
        "time_saved": round(time_saved, 2)
    }
