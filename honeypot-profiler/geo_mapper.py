"""
geo_mapper.py  –  World map of attack origins using Folium
Reads data/profiles.csv and writes data/geo_map.html
"""

import os
import pandas as pd

PROFILES_PATH = "data/profiles.csv"
GEO_MAP_PATH  = "data/geo_map.html"

SEVERITY_COLORS = {
    "Critical": "red",
    "High":     "orange",
    "Medium":   "beige",
    "Low":      "green",
}
PROFILE_COLORS = {
    "Targeted Attacker": "red",
    "Driven Explorer":   "orange",
    "Casual Scanner":    "green",
}


def generate_geo_map(profiles_path=PROFILES_PATH, output_path=GEO_MAP_PATH):
    try:
        import folium
        from folium.plugins import MarkerCluster
    except ImportError:
        print("[geo_mapper] folium not installed. pip install folium")
        return

    os.makedirs("data", exist_ok=True)

    if not os.path.exists(profiles_path):
        print(f"[geo_mapper] {profiles_path} not found.")
        return

    df = pd.read_csv(profiles_path)
    if "latitude" not in df.columns or "longitude" not in df.columns:
        print("[geo_mapper] lat/lon columns missing in profiles.csv")
        return

    m = folium.Map(
        location=[20, 0],
        zoom_start=2,
        tiles="CartoDB dark_matter",
    )
    cluster = MarkerCluster().add_to(m)

    for _, row in df.iterrows():
        try:
            lat = float(row["latitude"])
            lon = float(row["longitude"])
        except (ValueError, TypeError):
            continue

        profile  = row.get("attacker_profile", "Unknown")
        severity = row.get("mitre_severity",   "Low")
        color    = PROFILE_COLORS.get(profile, "blue")
        score    = row.get("threat_score", "N/A")

        popup_html = f"""
        <b>IP:</b> {row.get('ip_address','?')}<br>
        <b>Country:</b> {row.get('country','?')}<br>
        <b>Profile:</b> {profile}<br>
        <b>MITRE:</b> {row.get('mitre_id','?')} – {row.get('mitre_technique','?')}<br>
        <b>Severity:</b> {severity}<br>
        <b>Threat Score:</b> {score}<br>
        """
        folium.CircleMarker(
            location=[lat, lon],
            radius=5,
            color=color,
            fill=True,
            fill_color=color,
            fill_opacity=0.7,
            popup=folium.Popup(popup_html, max_width=260),
        ).add_to(cluster)

    m.save(output_path)
    print(f"[geo_mapper] Geo map saved → {output_path}")


if __name__ == "__main__":
    generate_geo_map()