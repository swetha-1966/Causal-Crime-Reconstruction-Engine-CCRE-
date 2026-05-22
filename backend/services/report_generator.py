"""
Incident Report Generator Service
Transforms structured CCRE pipeline output into a professional
SOC-grade incident report.

Produces all 7 mandatory sections:
  1. Executive Summary
  2. Root Cause Analysis
  3. Attack Progression (narrative)
  4. Critical Path
  5. Key Insights
  6. Risk Assessment
  7. Recommendations
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from models.schema import Event

logger = logging.getLogger(__name__)

from services.event_labels import EVENT_LABELS, normalize_event_label

# Severity classification for attack types
ATTACK_SEVERITY = {
    "phishing": "Critical",
    "brute_force": "High",
    "insider_threat": "Critical",
    "ransomware": "Critical",
    "supply_chain": "Critical",
    "credential_stuffing": "High",
    "watering_hole": "High",
    "zero_day": "Critical",
}

# Causal transition phrases (varied to avoid repetition)
TRANSITION_PHRASES = [
    "which led to",
    "enabling",
    "resulting in",
    "which facilitated",
    "allowing",
    "culminating in",
]


def _normalize_event(event_type: str) -> str:
    """Convert a raw event name to a human-readable security action."""
    return normalize_event_label(event_type)


def _parse_time(ts: str) -> Optional[str]:
    """Extract a displayable time string."""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%H:%M")
    except (ValueError, TypeError):
        # Might already be in HH:MM format
        return ts if ts else "N/A"


def _get_confidence_tier(score: float) -> dict:
    """Classify a confidence score into a risk tier."""
    if score > 0.75:
        return {
            "tier": "High",
            "description": "High confidence with strong evidence",
            "color": "accent",
        }
    elif score >= 0.55:
        return {
            "tier": "Moderate",
            "description": "Moderate confidence with consistent indicators",
            "color": "warning",
        }
    else:
        return {
            "tier": "Low",
            "description": "Low confidence requiring further investigation",
            "color": "danger",
        }


def _determine_severity(attack_type: str, risk_score: float) -> str:
    """Determine overall incident severity based primarily on risk score."""
    if risk_score >= 80:
        return "Critical"
    elif risk_score >= 60:
        return "High"
    elif risk_score >= 30:
        return "Medium"
    return "Low"


def _build_executive_summary(
    events: List[Event],
    attack_type: str,
    risk_score: float,
    critical_path_events: List[Event],
    severity: str,
) -> str:
    """Build 3-4 line executive summary."""
    first_event = events[0] if events else None
    last_event = events[-1] if events else None
    user = first_event.user if first_event else "unknown"

    # Determine time window
    start_time = _parse_time(first_event.timestamp) if first_event else "N/A"
    end_time = _parse_time(last_event.timestamp) if last_event else "N/A"

    # Determine what attacker achieved (final event)
    final_action = _normalize_event(last_event.event_type) if last_event else "unknown"
    initial_action = _normalize_event(first_event.event_type) if first_event else "unknown"

    # Extract metadata details for richer summary
    files_accessed = None
    data_volume = None
    for evt in events:
        if evt.metadata:
            if "files_accessed" in evt.metadata:
                files_accessed = evt.metadata["files_accessed"]
            if "data_volume_mb" in evt.metadata:
                data_volume = evt.metadata["data_volume_mb"]

    # Build summary
    parts = []
    parts.append(
        f"A targeted {attack_type.replace('_', ' ')} attack was executed against "
        f"the organization, compromising the account of {user}."
    )
    parts.append(
        f"The incident spanned from {start_time} to {end_time}, "
        f"progressing through {len(events)} distinct stages from "
        f"{initial_action.lower()} to {final_action.lower()}."
    )

    if files_accessed and data_volume:
        parts.append(
            f"The attacker successfully accessed {files_accessed:,} files "
            f"totalling {data_volume / 1000:.2f} GB of sensitive data."
        )

    parts.append(
        f"This incident is classified as {severity} severity "
        f"with a risk score of {risk_score:.0f}/100."
    )

    return " ".join(parts)


def _build_root_cause_analysis(
    events: List[Event],
    causal_links: List[Dict],
    critical_path_events: List[Event],
) -> dict:
    """Identify and explain root cause."""
    root_event = critical_path_events[0] if critical_path_events else (events[0] if events else None)

    if not root_event:
        return {
            "entry_point": "Unknown",
            "explanation": "Insufficient data to determine root cause.",
            "evidence": [],
        }

    normalized = _normalize_event(root_event.event_type)

    # Build evidence from metadata
    evidence = []
    meta = root_event.metadata or {}

    if root_event.event_type == "phishing_email":
        if "sender" in meta:
            evidence.append(f"Malicious sender: {meta['sender']}")
        if "subject" in meta:
            evidence.append(f"Social engineering lure: \"{meta['subject']}\"")
        if meta.get("has_link"):
            evidence.append("Email contained embedded malicious hyperlink")

    elif root_event.event_type == "port_scan":
        evidence.append("External reconnaissance activity detected")

    elif root_event.event_type == "software_update":
        evidence.append("Compromised third-party software supply chain")

    elif root_event.event_type == "vulnerability_scan":
        evidence.append("Attacker actively probing for exploitable vulnerabilities")

    # Find strongest outgoing link from root
    outgoing_conf = [
        l["confidence"] for l in causal_links
        if l.get("from_type") == root_event.event_type
    ]
    max_conf = max(outgoing_conf) if outgoing_conf else 0.0

    explanation = (
        f"The initial entry point was {normalized.lower()}, "
        f"targeting {root_event.user} via {root_event.resource}. "
        f"This event is identified as the root cause because it is the earliest "
        f"event in the high-confidence causal chain, with a forward causal "
        f"confidence of {max_conf:.0%}. "
    )

    if root_event.event_type == "phishing_email":
        explanation += (
            "The absence of effective email filtering and phishing-resistant "
            "authentication controls enabled the attacker to establish an "
            "initial foothold through social engineering."
        )

    return {
        "entry_point": normalized,
        "event_type": root_event.event_type,
        "user": root_event.user,
        "resource": root_event.resource,
        "timestamp": _parse_time(root_event.timestamp),
        "explanation": explanation,
        "evidence": evidence,
        "confidence": max_conf,
    }


def _build_attack_progression(
    events: List[Event],
    causal_links: List[Dict],
) -> str:
    """Build a clean narrative of the attack progression."""
    if not events:
        return "No events to analyze."

    if len(events) == 1:
        return f"A single event was detected: {_normalize_event(events[0].event_type).lower()}."

    # Group events logically and build narrative
    parts = []
    transition_idx = 0

    for i, event in enumerate(events):
        normalized = _normalize_event(event.event_type)
        time_str = _parse_time(event.timestamp)
        meta = event.metadata or {}

        if i == 0:
            # Opening
            detail = ""
            if event.event_type == "phishing_email":
                sender = meta.get("sender", "an external address")
                subject = meta.get("subject", "")
                detail = (
                    f" originating from {sender}"
                    f"{f', using the subject line \"{subject}\"' if subject else ''}"
                    f", delivered to {event.user}"
                )
            parts.append(
                f"The attack was initiated at {time_str} through "
                f"{normalized.lower()}{detail}."
            )

        elif i == len(events) - 1:
            # Closing
            detail = ""
            if event.event_type == "data_exfiltration":
                vol = meta.get("data_volume_mb")
                files = meta.get("files_accessed")
                method = meta.get("exfil_method", "").replace("_", " ")
                dest = meta.get("destination", "")
                if vol and files:
                    detail = (
                        f", with {files:,} files ({vol / 1000:.2f} GB) "
                        f"transferred via {method}"
                        f"{f' to {dest}' if dest else ''}"
                    )
            parts.append(
                f"This ultimately resulted in {normalized.lower()} "
                f"at {time_str}{detail}."
            )

        else:
            # Middle events — use varied transition language
            transition = TRANSITION_PHRASES[transition_idx % len(TRANSITION_PHRASES)]
            transition_idx += 1

            detail = ""
            if event.event_type == "link_clicked":
                url = meta.get("url", "")
                if url:
                    detail = f" at {url}"
            elif event.event_type == "credential_theft":
                method = meta.get("method", "").replace("_", " ")
                if method:
                    detail = f" via {method}"
            elif event.event_type == "login":
                src_ip = meta.get("source_ip", "")
                mfa = meta.get("mfa_bypassed", False)
                if src_ip:
                    detail = f" from external IP {src_ip}"
                if mfa:
                    detail += ", bypassing multi-factor authentication"
            elif event.event_type == "privilege_escalation":
                from_role = meta.get("from_role", "").replace("_", " ")
                to_role = meta.get("to_role", "").replace("_", " ")
                exploit = meta.get("exploit", "")
                tool = meta.get("tool_used", "")
                if from_role and to_role:
                    detail = f" from {from_role} to {to_role}"
                if exploit:
                    detail += f" using {exploit}"
                if tool:
                    detail += f" via {tool}"

            parts.append(
                f"This {transition} {normalized.lower()} "
                f"at {time_str}{detail}."
            )

    return " ".join(parts)


def _build_critical_path(
    critical_path_ids: List[str],
    events: List[Event],
) -> List[dict]:
    """Build displayable critical path steps."""
    steps = []
    event_map = {e.id: e for e in events}

    for eid in critical_path_ids:
        evt = event_map.get(eid)
        if evt:
            steps.append({
                "id": eid,
                "label": _normalize_event(evt.event_type),
                "event_type": evt.event_type,
                "timestamp": _parse_time(evt.timestamp),
            })

    return steps


def _build_key_insights(
    events: List[Event],
    causal_links: List[Dict],
    critical_path_events: List[Event],
) -> dict:
    """Determine key insights about the attack."""
    insights = {
        "enablers": [],
        "turning_point": None,
        "success_factors": [],
    }

    # What enabled the attack
    for evt in events:
        meta = evt.metadata or {}
        if evt.event_type == "phishing_email":
            insights["enablers"].append(
                "Lack of advanced email filtering and URL sandboxing allowed "
                "the phishing email to reach the target inbox unimpeded."
            )
        if evt.event_type == "login" and meta.get("mfa_bypassed"):
            insights["enablers"].append(
                "Weak or bypassable multi-factor authentication on the "
                f"corporate {evt.resource.replace('_', ' ')} enabled "
                "unauthorized access with stolen credentials."
            )
        if evt.event_type == "privilege_escalation":
            exploit = meta.get("exploit", "")
            if exploit:
                insights["enablers"].append(
                    f"Unpatched vulnerability ({exploit}) allowed "
                    "rapid privilege escalation to domain administrator level."
                )

    # Turning point — the event that escalated the attack
    for evt in critical_path_events:
        meta = evt.metadata or {}
        if evt.event_type == "login" and meta.get("mfa_bypassed"):
            insights["turning_point"] = (
                "The MFA bypass during VPN authentication was the decisive turning point. "
                "Before this, the incident was limited to credential theft. "
                "After, the attacker gained authenticated network access, "
                "transforming a contained phishing event into an active intrusion."
            )
            break
        elif evt.event_type == "privilege_escalation":
            to_role = meta.get("to_role", "admin").replace("_", " ")
            insights["turning_point"] = (
                f"Privilege escalation to {to_role} was the turning point, "
                "granting the attacker unrestricted access across the environment."
            )
            break

    if not insights["turning_point"]:
        # Fallback: midpoint of critical path
        mid = len(critical_path_events) // 2
        if mid < len(critical_path_events):
            evt = critical_path_events[mid]
            insights["turning_point"] = (
                f"{_normalize_event(evt.event_type)} at {_parse_time(evt.timestamp)} "
                "represented the critical escalation point in this incident."
            )

    # What made the attack successful
    for evt in events:
        meta = evt.metadata or {}
        if evt.event_type == "data_exfiltration":
            method = meta.get("exfil_method", "").replace("_", " ")
            if method:
                insights["success_factors"].append(
                    f"Use of {method} for data exfiltration evaded "
                    "content-level traffic inspection."
                )

    # Time-based insight
    if len(events) >= 2:
        start = _parse_time(events[0].timestamp)
        end = _parse_time(events[-1].timestamp)
        insights["success_factors"].append(
            f"The entire attack was executed within a compressed timeframe "
            f"({start} to {end}), outpacing detection and response capabilities."
        )

    return insights


def _build_risk_assessment(
    avg_confidence: float,
    risk_score: float,
    severity: str,
    causal_links: List[Dict],
    events: List[Event],
) -> dict:
    """Build risk assessment section."""
    tier = _get_confidence_tier(avg_confidence)

    # Extract notable risk factors
    risk_factors = []

    for evt in events:
        meta = evt.metadata or {}
        if meta.get("mfa_bypassed"):
            risk_factors.append("MFA bypass confirmed — critical authentication control failure")
        if evt.event_type == "privilege_escalation":
            risk_factors.append(
                f"Domain-level privilege escalation achieved via {meta.get('exploit', 'exploit')}"
            )
        if evt.event_type == "data_exfiltration":
            vol = meta.get("data_volume_mb")
            if vol:
                risk_factors.append(f"Confirmed data exfiltration: {vol / 1000:.2f} GB")

    return {
        "confidence_tier": tier,
        "avg_confidence": round(avg_confidence, 3),
        "risk_score": risk_score,
        "severity": severity,
        "risk_factors": risk_factors,
        "total_links": len(causal_links),
        "high_confidence_links": len([l for l in causal_links if l["confidence"] > 0.75]),
        "moderate_confidence_links": len([l for l in causal_links if 0.55 <= l["confidence"] <= 0.75]),
        "low_confidence_links": len([l for l in causal_links if l["confidence"] < 0.55]),
    }


def _build_recommendations(events: List[Event]) -> List[dict]:
    """Generate actionable recommendations based on attack indicators."""
    recs = []

    event_types = {e.event_type for e in events}
    all_meta = {}
    for e in events:
        all_meta.update(e.metadata or {})

    # Authentication
    if "credential_theft" in event_types or "login" in event_types:
        recs.append({
            "category": "Authentication Security",
            "icon": "🔐",
            "items": [
                "Enforce phishing-resistant MFA (FIDO2/hardware security keys) on all remote access points.",
                "Immediately rotate all credentials associated with the compromised account.",
                "Audit and restrict Domain Administrator assignments using least-privilege principles.",
            ],
        })

    # Vulnerability Management
    if "privilege_escalation" in event_types:
        exploit = all_meta.get("exploit", "")
        items = [
            "Conduct an emergency vulnerability scan across all production systems.",
            "Deploy behavioral detection rules for credential dumping tools (e.g., Mimikatz).",
        ]
        if exploit:
            items.insert(0, f"Patch {exploit} immediately across all affected hosts.")
        recs.append({
            "category": "Vulnerability Management",
            "icon": "🩹",
            "items": items,
        })

    # Monitoring
    if "data_exfiltration" in event_types or "data_access" in event_types:
        recs.append({
            "category": "Monitoring & Detection",
            "icon": "📡",
            "items": [
                "Enable geolocation-based anomaly alerting on all authentication services.",
                "Implement TLS/SSL inspection at network egress points.",
                "Configure data loss prevention (DLP) policies on file servers for bulk access detection.",
                "Deploy User and Entity Behavior Analytics (UEBA) for baseline deviation alerting.",
            ],
        })

    # User Awareness
    if "phishing_email" in event_types or "link_clicked" in event_types:
        recs.append({
            "category": "User Awareness",
            "icon": "🎓",
            "items": [
                "Conduct targeted phishing simulation exercises with mandatory remedial training.",
                "Deploy a one-click 'Report Phishing' button in the corporate email client.",
                "Issue an organization-wide advisory on credential-reset email scams.",
            ],
        })

    # Access Control
    if "lateral_movement" in event_types or "privilege_escalation" in event_types:
        recs.append({
            "category": "Access Control",
            "icon": "🔒",
            "items": [
                "Implement network micro-segmentation to limit lateral movement.",
                "Restrict privilege escalation paths within Active Directory.",
                "Enforce device compliance checks and certificate-based VPN authentication.",
            ],
        })

    # Default if nothing matched
    if not recs:
        recs.append({
            "category": "General Security",
            "icon": "🛡️",
            "items": [
                "Review and strengthen perimeter security controls.",
                "Enable comprehensive logging across all critical systems.",
                "Conduct a full security posture assessment.",
            ],
        })

    return recs


def generate_incident_report(
    timeline: List[Dict[str, Any]],
    causal_links: List[Dict[str, Any]],
    critical_path: List[str],
    insights: Dict[str, Any],
    confidence_scores: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Main entry point: Generate a structured SOC incident report
    from CCRE pipeline output.

    Returns a dictionary with all 7 report sections, ready
    for frontend rendering.
    """
    # Reconstruct Event objects from timeline dicts
    events = []
    for t in timeline:
        events.append(Event(**t))

    # Build event map for critical path resolution
    event_map = {e.id: e for e in events}
    critical_path_events = [event_map[eid] for eid in critical_path if eid in event_map]

    # Determine key parameters
    attack_type = insights.get("attack_type", "Unknown")
    risk_score = insights.get("risk_score", 0.0)
    avg_confidence = insights.get("avg_confidence", 0.0)
    severity = _determine_severity(attack_type, risk_score)

    # Generate report timestamp
    report_id = f"INC-{datetime.now().strftime('%Y-%m%d-%H%M')}"

    report = {
        "report_id": report_id,
        "generated_at": datetime.now().isoformat(),
        "severity": severity,
        "attack_type": attack_type,

        "executive_summary": _build_executive_summary(
            events, attack_type, risk_score, critical_path_events, severity
        ),

        "root_cause": _build_root_cause_analysis(
            events, causal_links, critical_path_events
        ),

        "attack_progression": _build_attack_progression(
            events, causal_links
        ),

        "critical_path": _build_critical_path(
            critical_path, events
        ),

        "key_insights": _build_key_insights(
            events, causal_links, critical_path_events
        ),

        "risk_assessment": _build_risk_assessment(
            avg_confidence, risk_score, severity,
            causal_links, events
        ),

        "recommendations": _build_recommendations(events),
    }

    logger.info(f"Incident report {report_id} generated: severity={severity}")
    return report
