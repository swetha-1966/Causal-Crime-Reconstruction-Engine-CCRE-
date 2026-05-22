"""
Pydantic models for the CCRE system.
Defines all data structures used across the pipeline.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class RawLog(BaseModel):
    """A single raw log entry from uploaded data."""
    event: str
    time: str
    user: Optional[str] = "unknown"
    resource: Optional[str] = "N/A"
    metadata: Optional[Dict[str, Any]] = {}


class Event(BaseModel):
    """A structured, normalized event extracted from a raw log."""
    id: str
    event_type: str
    user: str = "unknown"
    timestamp: str
    resource: str = "N/A"
    metadata: Dict[str, Any] = {}
    sequence: Optional[int] = None
    severity: Optional[str] = "medium"  # low, medium, high, critical


class CausalLink(BaseModel):
    """A directed causal relationship between two events."""
    from_event: str = Field(..., alias="from")
    to_event: str = Field(..., alias="to")
    confidence: float = Field(..., ge=0.0, le=1.0)
    rule: Optional[str] = None

    class Config:
        populate_by_name = True


class GraphNode(BaseModel):
    """A node in the causal graph."""
    id: str
    label: str
    event_type: str
    timestamp: str
    user: str = "unknown"
    severity: str = "medium"
    is_critical_path: bool = False


class GraphEdge(BaseModel):
    """An edge in the causal graph."""
    source: str
    target: str
    confidence: float
    label: Optional[str] = None
    is_critical_path: bool = False


class GraphData(BaseModel):
    """Complete graph representation."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class AnomalyInfo(BaseModel):
    """A detected anomaly in the event chain."""
    event_id: str
    event_type: str
    anomaly_type: str  # time_gap, orphan_event, unusual_pattern, severity_spike
    description: str
    severity: str = "medium"  # low, medium, high, critical
    score: float = 0.0


class InsightData(BaseModel):
    """Aggregated insights from the analysis."""
    root_cause: str
    root_cause_event_id: Optional[str] = None
    attack_type: str
    attack_type_confidence: float = 0.0
    risk_score: float = 0.0  # 0-100
    total_events: int = 0
    total_causal_links: int = 0
    avg_confidence: float = 0.0
    critical_path_length: int = 0
    anomaly_count: int = 0


class ProcessResult(BaseModel):
    """Full output of the CCRE pipeline."""
    timeline: List[Event]
    graph: GraphData
    explanation: str
    confidence_scores: List[Dict[str, Any]]
    critical_path: List[str] = []           # ordered list of event IDs
    anomalies: List[AnomalyInfo] = []
    insights: Optional[InsightData] = None
    evaluation: Optional[Dict[str, Any]] = None


class UploadResponse(BaseModel):
    """Response after uploading logs."""
    message: str
    event_count: int
    events: List[Event]
