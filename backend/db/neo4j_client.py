"""
Neo4j client for the CCRE system.
Handles connection, node/relationship creation, and graph retrieval.
Falls back gracefully if Neo4j is unavailable.
"""

import os
import logging
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

# Neo4j connection settings from environment
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "ccre_password")

# Try importing neo4j driver
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    logger.warning("neo4j package not installed. Running without Neo4j support.")


class Neo4jClient:
    """Client for interacting with Neo4j graph database."""

    def __init__(self):
        self.driver = None
        self.connected = False
        if NEO4J_AVAILABLE:
            try:
                self.driver = GraphDatabase.driver(
                    NEO4J_URI,
                    auth=(NEO4J_USER, NEO4J_PASSWORD)
                )
                # Test connectivity
                self.driver.verify_connectivity()
                self.connected = True
                logger.info(f"Connected to Neo4j at {NEO4J_URI}")
            except Exception as e:
                logger.warning(f"Could not connect to Neo4j: {e}. Running in fallback mode.")
                self.connected = False

    def close(self):
        """Close the Neo4j driver connection."""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed.")

    def clear_graph(self):
        """Remove all nodes and relationships from the database."""
        if not self.connected:
            return
        try:
            with self.driver.session() as session:
                session.run("MATCH (n) DETACH DELETE n")
                logger.info("Cleared all nodes and relationships from Neo4j.")
        except Exception as e:
            logger.error(f"Error clearing graph: {e}")

    def create_event_node(self, event_id: str, event_type: str,
                          timestamp: str, user: str = "unknown",
                          resource: str = "N/A"):
        """
        Create an Event node in Neo4j.
        
        Node structure:
            (:Event {id, event_type, timestamp, user, resource})
        """
        if not self.connected:
            return
        try:
            with self.driver.session() as session:
                session.run(
                    """
                    MERGE (e:Event {id: $id})
                    SET e.event_type = $event_type,
                        e.timestamp = $timestamp,
                        e.user = $user,
                        e.resource = $resource
                    """,
                    id=event_id,
                    event_type=event_type,
                    timestamp=timestamp,
                    user=user,
                    resource=resource
                )
        except Exception as e:
            logger.error(f"Error creating event node: {e}")

    def create_causal_link(self, from_id: str, to_id: str,
                           confidence: float, rule: str = ""):
        """
        Create a CAUSED relationship between two Event nodes.
        
        Relationship structure:
            (:Event)-[:CAUSED {confidence, rule}]->(:Event)
        """
        if not self.connected:
            return
        try:
            with self.driver.session() as session:
                session.run(
                    """
                    MATCH (a:Event {id: $from_id})
                    MATCH (b:Event {id: $to_id})
                    MERGE (a)-[r:CAUSED]->(b)
                    SET r.confidence = $confidence,
                        r.rule = $rule
                    """,
                    from_id=from_id,
                    to_id=to_id,
                    confidence=confidence,
                    rule=rule
                )
        except Exception as e:
            logger.error(f"Error creating causal link: {e}")

    def get_full_graph(self) -> Dict[str, Any]:
        """
        Retrieve the full graph from Neo4j.
        Returns dict with 'nodes' and 'edges' lists.
        """
        if not self.connected:
            return {"nodes": [], "edges": []}

        nodes = []
        edges = []
        try:
            with self.driver.session() as session:
                # Get all nodes
                result = session.run("MATCH (e:Event) RETURN e")
                for record in result:
                    node = record["e"]
                    nodes.append({
                        "id": node["id"],
                        "event_type": node.get("event_type", ""),
                        "timestamp": node.get("timestamp", ""),
                        "user": node.get("user", "unknown"),
                        "resource": node.get("resource", "N/A")
                    })

                # Get all relationships
                result = session.run(
                    """
                    MATCH (a:Event)-[r:CAUSED]->(b:Event)
                    RETURN a.id AS from_id, b.id AS to_id,
                           r.confidence AS confidence, r.rule AS rule
                    """
                )
                for record in result:
                    edges.append({
                        "source": record["from_id"],
                        "target": record["to_id"],
                        "confidence": record["confidence"],
                        "rule": record.get("rule", "")
                    })
        except Exception as e:
            logger.error(f"Error retrieving graph: {e}")

        return {"nodes": nodes, "edges": edges}


# Singleton instance
_client: Optional[Neo4jClient] = None


def get_neo4j_client() -> Neo4jClient:
    """Get or create the singleton Neo4j client instance."""
    global _client
    if _client is None:
        _client = Neo4jClient()
    return _client
