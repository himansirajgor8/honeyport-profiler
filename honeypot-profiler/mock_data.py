import pandas as pd
import numpy as np
import random
import os
from datetime import datetime, timedelta

def generate_mock_logs(n=500, save_path="data/mock_logs.csv"):
    os.makedirs("data", exist_ok=True)
    random.seed(42)
    np.random.seed(42)

    countries = [
        "China", "Russia", "USA", "Germany", "Brazil",
        "India", "Netherlands", "Ukraine", "Romania", "Iran",
        "South Korea", "France", "Japan", "Canada", "UK"
    ]
    country_coords = {
        "China":       (35.8617,  104.1954),
        "Russia":      (61.5240,  105.3188),
        "USA":         (37.0902,  -95.7129),
        "Germany":     (51.1657,   10.4515),
        "Brazil":      (-14.2350, -51.9253),
        "India":       (20.5937,   78.9629),
        "Netherlands": (52.1326,    5.2913),
        "Ukraine":     (48.3794,   31.1656),
        "Romania":     (45.9432,   24.9668),
        "Iran":        (32.4279,   53.6880),
        "South Korea": (35.9078,  127.7669),
        "France":      (46.2276,    2.2137),
        "Japan":       (36.2048,  138.2529),
        "Canada":      (56.1304,  -106.3468),
        "UK":          (55.3781,   -3.4360),
    }
    protocols   = ["SSH", "HTTP", "FTP", "Telnet", "RDP", "SMTP", "DNS"]
    attack_types = ["brute_force", "port_scan", "sql_injection",
                    "xss", "directory_traversal", "credential_stuffing"]

    base_time = datetime(2024, 1, 1, 0, 0, 0)
    records = []

    for i in range(n):
        country = random.choice(countries)
        lat, lon = country_coords[country]
        lat += random.uniform(-5, 5)
        lon += random.uniform(-5, 5)

        # Weighted hour distribution – more attacks at night (UTC)
        hour_weights = [3,2,2,2,2,3,4,5,6,7,8,8,7,7,8,9,9,10,10,9,8,7,5,4]
        hour = random.choices(range(24), weights=hour_weights, k=1)[0]
        minute  = random.randint(0, 59)
        second  = random.randint(0, 59)
        day_offset = random.randint(0, 29)
        ts = base_time + timedelta(days=day_offset, hours=hour,
                                   minutes=minute, seconds=second)

        login_attempts = random.randint(1, 200)
        session_duration = random.uniform(0.5, 120.0)
        unique_ports = random.randint(1, 50)
        payload_size = random.randint(100, 50000)

        records.append({
            "timestamp":        ts.strftime("%Y-%m-%d %H:%M:%S"),   # ISO string
            "ip_address":       f"{random.randint(1,254)}.{random.randint(0,254)}."
                                f"{random.randint(0,254)}.{random.randint(1,254)}",
            "country":          country,
            "latitude":         round(lat, 4),
            "longitude":        round(lon, 4),
            "protocol":         random.choice(protocols),
            "attack_type":      random.choice(attack_types),
            "login_attempts":   login_attempts,
            "session_duration": round(session_duration, 2),
            "unique_ports":     unique_ports,
            "payload_size":     payload_size,
        })

    df = pd.DataFrame(records)
    df.to_csv(save_path, index=False)
    print(f"[mock_data] Generated {n} logs → {save_path}")
    return df


if __name__ == "__main__":
    generate_mock_logs()