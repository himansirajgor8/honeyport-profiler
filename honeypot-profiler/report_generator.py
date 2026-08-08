"""
report_generator.py

Generate a PDF report using ReportLab including summary stats, profile
breakdown, top dangerous IPs and a geo map screenshot (if available).
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import pandas as pd
import os
from datetime import datetime
from typing import Optional


def generate_report(profiles_df: pd.DataFrame, logs_df: pd.DataFrame, map_png: Optional[str] = None, output_pdf: Optional[str] = None) -> str:
    """
    Generate a PDF report summarizing honeypot findings.

    Parameters:
    - profiles_df: DataFrame output from profiler
    - logs_df: Raw logs DataFrame
    - map_png: Optional path to a PNG screenshot of the geo map
    - output_pdf: Optional output filename. If not provided uses timestamped name.

    Returns:
    - Path to generated PDF
    """
    os.makedirs("reports", exist_ok=True)
    if output_pdf is None:
        output_pdf = f"reports/threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"

    c = canvas.Canvas(output_pdf, pagesize=A4)
    width, height = A4
    styles = getSampleStyleSheet()

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(30, height - 40, "Honeypot Threat Report")
    c.setFont("Helvetica", 9)
    c.drawString(30, height - 55, f"Generated: {datetime.utcnow().isoformat()} UTC")

    # Summary stats
    total_attacks = len(logs_df) if logs_df is not None else 0
    unique_ips = profiles_df["ip_address"].nunique() if (profiles_df is not None and not profiles_df.empty) else 0
    top_country = None
    if profiles_df is not None and "country" in profiles_df.columns:
        top_country = profiles_df["country"].fillna("Unknown").value_counts().idxmax()

    summary_y = height - 90
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, summary_y, "Summary")
    c.setFont("Helvetica", 10)
    c.drawString(40, summary_y - 16, f"Total attacks: {total_attacks}")
    c.drawString(40, summary_y - 32, f"Unique attacking IPs: {unique_ips}")
    c.drawString(40, summary_y - 48, f"Top country: {top_country}")

    # Attacker profile breakdown table
    table_y = summary_y - 100
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, table_y + 20, "Attacker Profile Breakdown")

    if profiles_df is not None and "attacker_profile" in profiles_df.columns:
        breakdown = profiles_df["attacker_profile"].value_counts().reset_index()
        breakdown.columns = ["Profile", "Count"]
        data = [breakdown.columns.tolist()] + breakdown.values.tolist()
        t = Table(data, colWidths=[150, 80])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        w, h = t.wrapOn(c, width - 60, 200)
        t.drawOn(c, 40, table_y - h)
        next_y = table_y - h - 20
    else:
        c.drawString(40, table_y - 10, "No profile data available")
        next_y = table_y - 30

    # Top 5 most dangerous IPs
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, next_y, "Top 5 Most Dangerous IPs")
    next_y -= 16
    if profiles_df is not None and not profiles_df.empty:
        top5 = profiles_df.sort_values(by="unique_ports", ascending=False).head(5)
        for _, r in top5.iterrows():
            line = f"{r.get('ip_address')} - Profile: {r.get('attacker_profile')} - Unique Ports: {int(r.get('unique_ports', 0))} - Country: {r.get('country')}"
            c.setFont("Helvetica", 9)
            c.drawString(40, next_y, line)
            next_y -= 12
    else:
        c.setFont("Helvetica", 9)
        c.drawString(40, next_y, "No IPs available")
        next_y -= 12

    # Include map PNG if available
    if map_png and os.path.exists(map_png):
        try:
            # Place the image at the bottom half of the page
            c.drawImage(map_png, 40, 60, width=520, preserveAspectRatio=True, mask='auto')
        except Exception:
            c.setFont("Helvetica", 9)
            c.drawString(40, next_y, f"Could not embed map image: {map_png}")
    else:
        c.setFont("Helvetica", 9)
        c.drawString(40, next_y, "Map image not available. See data/map.html for interactive map.")

    c.showPage()
    c.save()

    return output_pdf


if __name__ == "__main__":
    import pandas as pd
    logs = pd.read_csv("data/logs.csv") if os.path.exists("data/logs.csv") else pd.DataFrame()
    profiles = pd.read_csv("data/profiles.csv") if os.path.exists("data/profiles.csv") else pd.DataFrame()
    out = generate_report(profiles, logs, map_png="data/map.png")
    print("Report generated:", out)
