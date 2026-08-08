import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import os

FEATURE_COLS = ["login_attempts", "session_duration", "unique_ports", "payload_size"]

CLUSTER_LABEL_MAP = {
    # Will be determined dynamically by centroid analysis
}

def _assign_labels(kmeans, scaler, n_clusters=3):
    """
    Determine human-readable label for each cluster by inspecting
    the (unscaled) centroid values of login_attempts + unique_ports.
    """
    centers = scaler.inverse_transform(kmeans.cluster_centers_)
    centers_df = pd.DataFrame(centers, columns=FEATURE_COLS)

    # Score = login_attempts * 0.6 + unique_ports * 0.4  (normalised 0-1)
    score = (centers_df["login_attempts"] / centers_df["login_attempts"].max() * 0.6 +
             centers_df["unique_ports"]   / centers_df["unique_ports"].max()   * 0.4)

    sorted_idx = score.argsort().tolist()   # low → high threat
    labels = ["Casual Scanner", "Driven Explorer", "Targeted Attacker"]
    return {cluster_id: labels[rank] for rank, cluster_id in enumerate(sorted_idx)}


def compute_threat_score(row: pd.Series) -> int:
    """
    Threat Score 0-100:
      Targeted Attacker  → 70  base, +30 scaled by login_attempts (100-200 range)
      Driven Explorer    → 35  base, +45 scaled by login_attempts (50-150 range)
      Casual Scanner     →  5  base, +35 scaled by login_attempts (1-50 range)
    """
    profile   = row["attacker_profile"]
    attempts  = row["login_attempts"]

    if profile == "Targeted Attacker":
        # 90-100 for high attempts
        base  = 70
        extra = min(30, int((attempts / 200) * 30))
    elif profile == "Driven Explorer":
        # 50-80 for medium attempts
        base  = 35
        extra = min(45, int((attempts / 150) * 45))
    else:  # Casual Scanner
        # 10-40 for low attempts
        base  = 5
        extra = min(35, int((attempts / 50)  * 35))

    score = base + extra
    return max(0, min(100, score))


def run_profiler(logs_path="data/mock_logs.csv",
                 profiles_path="data/profiles.csv",
                 n_clusters=3):
    os.makedirs("data", exist_ok=True)

    df = pd.read_csv(logs_path)
    print(f"[profiler] Loaded {len(df)} rows from {logs_path}")

    # ── Feature matrix ──────────────────────────────────────────────
    X = df[FEATURE_COLS].copy()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── KMeans ──────────────────────────────────────────────────────
    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    km.fit(X_scaled)
    df["cluster"] = km.labels_

    # ── Dynamic label assignment ─────────────────────────────────────
    label_map = _assign_labels(km, scaler, n_clusters)
    df["attacker_profile"] = df["cluster"].map(label_map)

    # ── Threat Score ─────────────────────────────────────────────────
    df["threat_score"] = df.apply(compute_threat_score, axis=1)

    # ── Save ─────────────────────────────────────────────────────────
    df.to_csv(profiles_path, index=False)
    print(f"[profiler] Profiles saved → {profiles_path}")
    print(df["attacker_profile"].value_counts().to_string())
    return df


if __name__ == "__main__":
    run_profiler()