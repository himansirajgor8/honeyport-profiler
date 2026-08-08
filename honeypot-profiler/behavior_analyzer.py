import pandas as pd
import numpy as np

def analyze_behavior(df):
    df = df.copy()

    # TIMING BEHAVIOR
    df["attack_speed"] = df["session_duration"] / (df["login_attempts"] + 1)
    df["is_night_attacker"] = df["hour"].between(0, 6) if "hour" in df.columns else False
    df["preferred_hour"] = df.get("hour", 0)

    # PERSISTENCE BEHAVIOR
    df["retry_rate"] = df["login_attempts"] / (df["session_duration"] + 1)
    df["is_persistent"] = df["login_attempts"] > 50
    df["gave_up_quickly"] = df["session_duration"] < 10

    # TARGETING BEHAVIOR
    df["is_focused"] = df["unique_ports"] <= 5
    df["is_scanner"] = ~df["is_focused"]

    # STEALTH BEHAVIOR
    df["is_slow_attacker"] = df["attack_speed"] > 5
    df["is_aggressive"] = df["attack_speed"] < 1

    # STEALTH SCORE (0-100)
    df["stealth_score"] = (
        df["is_slow_attacker"].astype(int) * 30 +
        df["is_persistent"].astype(int) * 25 +
        df["is_focused"].astype(int) * 25 +
        df["is_night_attacker"].astype(int) * 20
    ).clip(0, 100)

    return df


def classify_behavior_persona(row):
    is_aggressive = row.get("is_aggressive", False)
    is_slow = row.get("is_slow_attacker", False)
    is_persistent = row.get("is_persistent", False)
    is_focused = row.get("is_focused", False)
    is_night = row.get("is_night_attacker", False)
    is_scanner = row.get("is_scanner", False)
    gave_up = row.get("gave_up_quickly", False)

    # APT Actor — most dangerous
    if is_slow and is_persistent and is_focused and is_night:
        return "APT Actor"

    # Stealth Ninja
    elif is_slow and is_persistent and is_focused:
        return "Stealth Ninja"

    # Script Kiddie
    elif is_aggressive and is_scanner:
        return "Script Kiddie"

    # Researcher/Scanner
    elif is_scanner and not is_persistent:
        return "Researcher/Scanner"

    # Opportunist
    elif gave_up and not is_persistent:
        return "Opportunist"

    # Default
    else:
        return "Script Kiddie"


def add_behavior_to_profiles():
    df = pd.read_csv("data/profiles.csv")

    # Parse timestamp if exists
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["hour"] = df["timestamp"].dt.hour.fillna(12).astype(int)

    # Analyze behavior
    df = analyze_behavior(df)

    # Classify persona
    df["behavior_persona"] = df.apply(classify_behavior_persona, axis=1)

    # Save back
    df.to_csv("data/profiles.csv", index=False)
    print(f"[behavior] Personas added → {df['behavior_persona'].value_counts().to_dict()}")


def generate_behavior_report(df):
    return {
        "persona_distribution": df["behavior_persona"].value_counts().to_dict(),
        "apt_actors": df[df["behavior_persona"] == "APT Actor"][
            ["source_ip", "country", "stealth_score", "login_attempts"]
        ].head(10).to_dict("records"),
        "peak_attack_hour": int(df["hour"].mode()[0]) if "hour" in df.columns else 0,
        "avg_stealth_by_persona": df.groupby("behavior_persona")["stealth_score"].mean().to_dict(),
    }


if __name__ == "__main__":
    add_behavior_to_profiles()