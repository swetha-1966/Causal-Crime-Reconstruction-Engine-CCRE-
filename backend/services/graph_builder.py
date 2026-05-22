"""
Graph Builder Service
Converts events into graph nodes and causal links into edges.
Outputs strictly to Cytoscape JSON format.
Supports layered attack graphs with node levels and edge weights.
"""

import logging
from typing import List, Dict, Any

from models.schema import Event
from db.neo4j_client import get_neo4j_client
from services.event_labels import normalize_event_label

logger = logging.getLogger(__name__)


def build_graph_nodes(events: List[Event], attack_graph_nodes: List[Dict] = None) -> List[Dict[str, Any]]:
    """
    Convert Event objects into Cytoscape Node dicts.
    If attack_graph_nodes (from LLM) are provided, use their level assignments.
    """
    # Build level lookup from attack graph nodes
    level_map = {}
    if attack_graph_nodes:
        for ag_node in attack_graph_nodes:
            if isinstance(ag_node, dict):
                level_map[ag_node.get("id", "")] = ag_node.get("level", 0)

    nodes = []
    unique_ids = set()
    for event in events:
        if event.event_type not in unique_ids:
            unique_ids.add(event.event_type)
            label = normalize_event_label(event.event_type)
            level = level_map.get(event.event_type, 0)
            nodes.append({
                "data": {
                    "id": event.event_type,
                    "label": label,
                    "event_type": event.event_type,
                    "timestamp": event.timestamp,
                    "user": event.user,
                    "severity": event.severity or "medium",
                    "is_critical_path": False,
                    "level": level
                }
            })
    return nodes


def build_graph_edges(causal_links: List[Any]) -> List[Dict[str, Any]]:
    """
    Convert causal link structures into Cytoscape Edge dicts.
    Supports:
    - {"from": "A", "to": "B", "weight": 0.8, "reason": "..."} (new layered schema)
    - {"from": "A", "to": "B", "reason": "..."} (RAG schema)
    - ["A", "B"] (legacy list format)
    - {"source": "A", "target": "B"} (legacy dict format)
    """
    edges = []
    for link in causal_links:
        try:
            source, target, label = None, None, "LLM Inferred"
            weight = 0.7
            
            # Handle Dict format {"from": "A", "to": "B", "reason": "..."}
            if isinstance(link, dict):
                source = link.get("from", link.get("source"))
                target = link.get("to", link.get("target"))
                label = link.get("reason", link.get("rule", link.get("label", "causal link")))
                # Extract weight (new layered graph field)
                raw_weight = link.get("weight", link.get("confidence", None))
                strength = link.get("strength", "")
                if raw_weight is not None:
                    try:
                        weight = float(raw_weight)
                        weight = max(0.0, min(1.0, weight))
                    except (ValueError, TypeError):
                        weight = 0.7
                elif strength:
                    weight = 0.85 if strength == "Strong" else 0.65 if strength == "Moderate" else 0.45
                else:
                    weight = 0.7
            # Handle List format ["A", "B"]
            elif isinstance(link, list) and len(link) >= 2:
                source, target = str(link[0]), str(link[1])
                if len(link) > 2:
                    label = str(link[2])
            
            if source and target:
                edges.append({
                    "data": {
                        "source": source,
                        "target": target,
                        "weight": round(weight, 2),
                        "confidence": round(weight, 2),  # Alias for backward compat
                        "label": label,
                        "is_critical_path": True
                    }
                })
        except Exception as e:
            logger.warning(f"Failed to parse edge {link}: {e}")
            continue
            
    return edges


def persist_to_neo4j(events: List[Event], edges: List[Dict[str, Any]]):
    """Store the graph in Neo4j. Skips silently if unavailable."""
    client = get_neo4j_client()
    if not client.connected:
        logger.info("Neo4j not available. Skipping persistence.")
        return
    try:
        client.clear_graph()
        unique_events = {}
        for event in events:
            if event.event_type not in unique_events:
                unique_events[event.event_type] = event
                client.create_event_node(
                    event_id=event.event_type, event_type=event.event_type,
                    timestamp=event.timestamp, user=event.user, resource=event.resource
                )
        for edge in edges:
            client.create_causal_link(
                from_id=edge["data"]["source"], to_id=edge["data"]["target"],
                confidence=edge["data"].get("weight", edge["data"].get("confidence", 0.99)), 
                rule=edge["data"].get("label", "LLM")
            )
        logger.info(f"Persisted to Neo4j.")
    except Exception as e:
        logger.warning(f"Neo4j persistence error: {e}")


def build_graph(events: List[Event], causal_links: List[Any],
                persist: bool = True, attack_graph_nodes: List[Dict] = None) -> Dict[str, Any]:
    """Main entry point: build graph and optionally persist to Neo4j."""
    nodes = build_graph_nodes(events, attack_graph_nodes=attack_graph_nodes)
    edges = build_graph_edges(causal_links)
    if persist:
        persist_to_neo4j(events, edges)
    logger.info(f"Built Cytoscape graph: {len(nodes)} nodes, {len(edges)} edges.")
    return {"nodes": nodes, "edges": edges}
