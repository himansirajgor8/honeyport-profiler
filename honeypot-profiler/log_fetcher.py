"""
log_fetcher.py

Connects to Elasticsearch and fetches T-Pot honeypot logs, parses required
fields and returns a clean pandas DataFrame.
"""
from elasticsearch import Elasticsearch
import pandas as pd
from datetime import datetime
from typing import Optional


def fetch_logs(es_host: str = "http://localhost:9200", index: str = "tpot-*", size: int = 10000, save_csv: Optional[str] = None) -> pd.DataFrame:
    """
    Connect to Elasticsearch and fetch recent honeypot logs from T-Pot.

    Parameters:
    - es_host: Elasticsearch host URL (default: http://localhost:9200)
    - index: Index pattern to query (default: tpot-*)
    - size: Maximum number of records to fetch (default: 10000)
    - save_csv: Optional path to save fetched logs as CSV

    Returns:
    - pandas.DataFrame with cleaned columns:
      ['source_ip','timestamp','port','protocol','login_attempts','session_duration','country','asn']
    """
    # Connect to Elasticsearch
    es = Elasticsearch([es_host])

    # Basic query to fetch logs that have a source IP
    query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "source_ip"}}
                ]
            }
        },
        "size": size,
        "_source": ["source_ip", "timestamp", "port", "protocol", "login_attempts", "session_duration", "country", "asn"]
    }

    # Execute search
    resp = es.search(index=index, body=query, track_total_hits=False)
    hits = resp.get("hits", {}).get("hits", [])

    records = []
    for h in hits:
        src = h.get("_source", {})
        # Pull fields safely with defaults
        record = {
            "source_ip": src.get("source_ip") or src.get("src_ip") or src.get("src"),
            "timestamp": src.get("timestamp") or src.get("@timestamp") or None,
            "port": src.get("port") or src.get("dport") or None,
            "protocol": src.get("protocol") or src.get("proto") or None,
            "login_attempts": src.get("login_attempts") or src.get("auth_attempts") or 0,
            "session_duration": src.get("session_duration") or src.get("duration") or 0,
            "country": src.get("country") or None,
            "asn": src.get("asn") or src.get("as") or None,
        }
        records.append(record)

    # Create DataFrame
    df = pd.DataFrame(records)

    # Clean and coerce types
    if "timestamp" in df.columns:
        # try to parse timestamps
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if "port" in df.columns:
        df["port"] = pd.to_numeric(df["port"], errors="coerce")
    df["login_attempts"] = pd.to_numeric(df.get("login_attempts", 0), errors="coerce").fillna(0).astype(int)
    df["session_duration"] = pd.to_numeric(df.get("session_duration", 0), errors="coerce").fillna(0.0)

    # Drop rows without an IP
    df = df.dropna(subset=["source_ip"]).reset_index(drop=True)

    # Optionally save to CSV for downstream modules
    if save_csv:
        df.to_csv(save_csv, index=False)

    return df


if __name__ == "__main__":
    # quick local test runner
    df = fetch_logs(save_csv="data/logs.csv")
    print(f"Fetched {len(df)} records")
