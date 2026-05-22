"""
Evaluation Module: Reconstruction Accuracy
Calculates edge-based accuracy, precision, recall, and F1 score for causal graph reconstruction.
"""
from typing import List, Tuple, Set
import logging

logger = logging.getLogger(__name__)

def _get_edge_set(edges: List[Tuple[str, str]]) -> Set[Tuple[str, str]]:
    """Convert a list of (source, target) tuples into a set for fast comparison."""
    return set(edges)

def compute_edge_accuracy(predicted_edges: List[Tuple[str, str]], true_edges: List[Tuple[str, str]]) -> float:
    """
    Compute overall edge accuracy.
    accuracy = correct_edges / total_true_edges
    """
    if not true_edges:
        return 0.0
    pred_set = _get_edge_set(predicted_edges)
    true_set = _get_edge_set(true_edges)
    correct_edges = len(pred_set.intersection(true_set))
    
    return correct_edges / len(true_set)

def compute_precision(predicted_edges: List[Tuple[str, str]], true_edges: List[Tuple[str, str]]) -> float:
    """
    Compute precision.
    precision = correct_edges / predicted_edges
    """
    if not predicted_edges:
        return 0.0
    pred_set = _get_edge_set(predicted_edges)
    true_set = _get_edge_set(true_edges)
    correct_edges = len(pred_set.intersection(true_set))
    
    return correct_edges / len(pred_set)

def compute_recall(predicted_edges: List[Tuple[str, str]], true_edges: List[Tuple[str, str]]) -> float:
    """
    Compute recall.
    recall = correct_edges / total_true_edges
    """
    if not true_edges:
        return 0.0
    pred_set = _get_edge_set(predicted_edges)
    true_set = _get_edge_set(true_edges)
    correct_edges = len(pred_set.intersection(true_set))
    
    return correct_edges / len(true_set)

def compute_f1(precision: float, recall: float) -> float:
    """
    Compute F1 Score.
    f1 = 2 * (precision * recall) / (precision + recall)
    """
    if precision + recall == 0:
        return 0.0
    return 2 * (precision * recall) / (precision + recall)

def evaluate_accuracy(predicted_edges: List[Tuple[str, str]], true_edges: List[Tuple[str, str]]) -> dict:
    """
    Evaluate full accuracy metrics.
    """
    accuracy = compute_edge_accuracy(predicted_edges, true_edges)
    precision = compute_precision(predicted_edges, true_edges)
    recall = compute_recall(predicted_edges, true_edges)
    f1_score = compute_f1(precision, recall)
    
    logger.info("Accuracy calculated successfully")
    return {
        "edge_accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4)
    }
