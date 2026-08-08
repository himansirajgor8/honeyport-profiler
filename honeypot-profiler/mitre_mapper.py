"""
mitre_mapper.py
Maps each attacker row to a MITRE ATT&CK technique based on attack_type.
Adds columns: mitre_id, mitre_technique, mitre_tactic, mitre_severity
"""

import pandas as pd
import os

# ── MITRE ATT&CK lookup ────────────────────────────────────────────────────────
# Format: attack_type → (technique_id, technique_name, tactic, base_severity)
MITRE_MAP = {
    "brute_force": (
        "T1110",
        "Brute Force",
        "Credential Access",
        "High",
    ),
    "port_scan": (
        "T1046",
        "Network Service Discovery",
        "Discovery",
        "Medium",
    ),
    "sql_injection": (
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "Critical",
    ),
    "xss": (
        "T1189",
        "Drive-by Compromise",
        "Initial Access",
        "High",
    ),
    "directory_traversal": (
        "T1083",
        "File and Directory Discovery",
        "Discovery",
        "Medium",
    ),
    "credential_stuffing": (
        "T1078",
        "Valid Accounts",
        "Defense Evasion",
        "Critical",
    ),
}

DEFAULT_ENTRY = ("T1595", "Active Scanning", "Reconnaissance", "Low")

# Elevate severity for Targeted Attacker
SEVERITY_ELEVATE = {
    "Low":    "Medium",
    "Medium": "High",
    "High":   "Critical",
    "Critical": "Critical",
}


def _get_mitre_row(attack_type: str, attacker_profile: str) -> tuple:
    entry = MITRE_MAP.get(str(attack_type).lower().strip(), DEFAULT_ENTRY)
    mitre_id, technique, tactic, severity = entry

    # Elevate severity for most dangerous profile
    if attacker_profile == "Targeted Attacker":
        severity = SEVERITY_ELEVATE.get(severity, severity)

    return mitre_id, technique, tactic, severity


def add_mitre_to_profiles(profiles_path: str = "data/profiles.csv") -> pd.DataFrame:
    if not os.path.exists(profiles_path):
        raise FileNotFoundError(
            f"[mitre_mapper] {profiles_path} not found. "
            "Run profiler first (python main.py --mock --profile)."
        )

    df = pd.read_csv(profiles_path)
    print(f"[mitre_mapper] Loaded {len(df)} rows from {profiles_path}")

    results = df.apply(
        lambda row: _get_mitre_row(
            row.get("attack_type", ""),
            row.get("attacker_profile", ""),
        ),
        axis=1,
        result_type="expand",
    )
    results.columns = ["mitre_id", "mitre_technique", "mitre_tactic", "mitre_severity"]

    # Drop existing MITRE columns if present (re-run safe)
    for col in results.columns:
        if col in df.columns:
            df.drop(columns=[col], inplace=True)

    df = pd.concat([df, results], axis=1)
    df.to_csv(profiles_path, index=False)
    print(f"[mitre_mapper] MITRE columns added → {profiles_path}")
    print(df["mitre_severity"].value_counts().to_string())
    return df


if __name__ == "__main__":
    add_mitre_to_profiles()