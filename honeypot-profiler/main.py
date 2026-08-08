import argparse
import os
import sys
from report_generator import generate_report



def main():
    parser = argparse.ArgumentParser(description="Honeypot Attacker Profiling System")
    parser.add_argument("--mock",      action="store_true", help="Generate mock data")
    parser.add_argument("--profile",   action="store_true", help="Run ML profiler")
    parser.add_argument("--dashboard", action="store_true", help="Launch dashboard")
    parser.add_argument("--report",    action="store_true", help="Generate PDF report")
    parser.add_argument("--geo",       action="store_true", help="Generate geo map")
    args = parser.parse_args()

    # ── Step 1: Mock Data ──
    if args.mock:
        print("\n[main] ── Step 1: Generating mock data ──")
        try:
            from mock_data import generate_mock_logs
            generate_mock_logs()
        except Exception as e:
            print(f"[main] ERROR in mock_data: {e}")

    # ── Step 2: Profiler ──
    if args.profile:
        print("\n[main] ── Step 2: Running profiler ──")
        try:
            from profiler import run_profiler
            run_profiler()
        except Exception as e:
            print(f"[main] ERROR in profiler: {e}")

        # ── Step 2b: MITRE Mapping ──
        print("\n[main] ── Step 2b: Mapping to MITRE ATT&CK ──")
        try:
            from mitre_mapper import add_mitre_to_profiles
            add_mitre_to_profiles()
        except Exception as e:
            print(f"[main] ERROR in mitre_mapper: {e}")

        # ── Step 2c: Behavior Analysis ──
        print("\n[main] ── Step 2c: Analyzing attacker behavior ──")
        try:
            from behavior_analyzer import add_behavior_to_profiles
            add_behavior_to_profiles()
        except Exception as e:
            print(f"[main] ERROR in behavior_analyzer: {e}")

    # ── Step 3: Geo Map ──

    if args.geo:
        print("\n[main] ── Step 3: Generating geo map ──")
        try:
            from geo_mapper import generate_geo_map
            generate_geo_map()
        except Exception as e:
            print(f"[main] ERROR in geo_mapper: {e}")

    # ── Step 4: PDF Report ──
    if args.report:
        print("\n[main] ── Step 4: Generating PDF report ──")
        try:
            import pandas as pd
            from report_generator import generate_report

            profiles_df = pd.read_csv("data/profiles.csv")
            logs_df = pd.read_csv("data/mock_logs.csv")

            output = generate_report(profiles_df, logs_df)
            print(f"[main] Report generated: {output}")

        except Exception as e:
            print(f"[main] ERROR in report_generator: {e}")

    # ── Step 5: Dashboard ──
    if args.dashboard:
        print("\n[main] ── Step 5: Starting dashboard ──")
        if not os.path.exists("data/profiles.csv"):
            print("[main] ERROR: data/profiles.csv not found!")
            print("Run: python main.py --mock --profile first")
            sys.exit(1)
        from dashboard import run_dashboard
        run_dashboard(debug=False)


if __name__ == "__main__":
    main()