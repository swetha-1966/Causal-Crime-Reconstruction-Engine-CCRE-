"""
Event Labels — Shared utility for human-readable event type normalization.
Extracted from legacy probabilistic_engine to eliminate dead-code import chains.
"""

EVENT_LABELS = {
    "phishing_email": "Phishing-based credential compromise",
    "link_clicked": "User interaction with malicious link",
    "credential_theft": "Credential exposure",
    "credential_stuffing": "Automated credential stuffing attack",
    "login": "Unauthorized system access",
    "privilege_escalation": "Privilege escalation",
    "lateral_movement": "Lateral movement within network",
    "data_access": "Sensitive data access",
    "data_exfiltration": "Data exfiltration",
    "data_breach": "Confirmed data breach",
    "ransomware_deployed": "Ransomware deployment",
    "malware_download": "Malware payload delivery",
    "code_execution": "Arbitrary code execution",
    "backdoor_installed": "Persistent backdoor installation",
    "command_and_control": "Command-and-control communication",
    "port_scan": "Network reconnaissance via port scanning",
    "brute_force_attempt": "Brute-force authentication attack",
    "software_update": "Compromised software update",
    "vulnerability_scan": "Vulnerability reconnaissance",
    "exploit_attempt": "Active exploitation attempt",
    "drive_by_download": "Drive-by download attack",
    "website_compromised": "Trusted website compromise",
    "account_takeover": "Full account takeover",
    "unusual_access_pattern": "Anomalous access behaviour",
    "large_download": "High-volume data download",
    "system_compromised": "Full system compromise",
}


def normalize_event_label(event_type: str) -> str:
    """Convert raw event name to human-readable security action."""
    return EVENT_LABELS.get(event_type, event_type.replace("_", " ").title())
