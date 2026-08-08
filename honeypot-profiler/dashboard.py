
import os
import base64
import tempfile

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output

# ── Paths ─────────────────────────────────────────────────────────────────────
PROFILES_PATH = "data/profiles.csv"
GEO_MAP_PATH  = "data/geo_map.html"

# ── Dark colour palette ────────────────────────────────────────────────────────
DARK_BG        = "#0d1117"
CARD_BG        = "#161b22"
BORDER_COL     = "#30363d"
TEXT_COL       = "#e6edf3"
MUTED_COL      = "#8b949e"
ACCENT_TEAL    = "#58a6ff"
ACCENT_GREEN   = "#3fb950"
ACCENT_ORANGE  = "#d29922"
ACCENT_RED     = "#f85149"
ACCENT_PURPLE  = "#bc8cff"
ACCENT_YELLOW  = "#e3b341"

SEVERITY_COLORS = {
    "Critical": ACCENT_RED,
    "High":     ACCENT_ORANGE,
    "Medium":   ACCENT_YELLOW,
    "Low":      ACCENT_GREEN,
}
PROFILE_COLORS = {
    "Targeted Attacker": ACCENT_RED,
    "Driven Explorer":   ACCENT_ORANGE,
    "Casual Scanner":    ACCENT_GREEN,
}

PLOTLY_DARK = dict(
    paper_bgcolor=CARD_BG,
    plot_bgcolor=CARD_BG,
    font=dict(color=TEXT_COL, family="'JetBrains Mono', 'Fira Code', monospace"),
    margin=dict(l=40, r=20, t=40, b=40),
)

# ── Helper ─────────────────────────────────────────────────────────────────────

def load_profiles() -> pd.DataFrame:
    if not os.path.exists(PROFILES_PATH):
        return pd.DataFrame()
    df = pd.read_csv(PROFILES_PATH)
    # ── BUG FIX 1: robust timestamp parsing ──────────────────────────────────
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df.dropna(subset=["timestamp"], inplace=True)
        df["hour"] = df["timestamp"].dt.hour
    return df


def card(children, style=None):
    base = dict(
        background=CARD_BG,
        border=f"1px solid {BORDER_COL}",
        borderRadius="8px",
        padding="20px",
        marginBottom="16px",
    )
    if style:
        base.update(style)
    return html.Div(children, style=base)


# ── Chart builders ─────────────────────────────────────────────────────────────

def fig_attack_frequency(df: pd.DataFrame) -> go.Figure:
    """Line chart – attacks per hour (BUG FIX 1)."""
    if df.empty or "hour" not in df.columns:
        fig = go.Figure()
        fig.update_layout(title="No data", **PLOTLY_DARK)
        return fig

    hourly = df.groupby("hour").size().reindex(range(24), fill_value=0).reset_index()
    hourly.columns = ["hour", "count"]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=hourly["hour"],
        y=hourly["count"],
        mode="lines+markers",
        line=dict(color=ACCENT_TEAL, width=2),
        marker=dict(size=6, color=ACCENT_TEAL),
        fill="tozeroy",
        fillcolor=f"rgba(88,166,255,0.12)",
        name="Attacks",
    ))
    fig.update_layout(
    title="Attack Frequency by Hour (UTC)",
    **PLOTLY_DARK,
    )
    fig.update_xaxes(
    tickmode="linear",
    dtick=2,
    gridcolor=BORDER_COL,
    zerolinecolor=BORDER_COL,
    title="Hour of Day"
    )
    fig.update_yaxes(
    gridcolor=BORDER_COL,
    zerolinecolor=BORDER_COL,
    title="Number of Attacks"
)
    return fig


def fig_profile_pie(df: pd.DataFrame) -> go.Figure:
    if df.empty or "attacker_profile" not in df.columns:
        return go.Figure().update_layout(**PLOTLY_DARK)

    counts = df["attacker_profile"].value_counts()
    fig = go.Figure(go.Pie(
        labels=counts.index,
        values=counts.values,
        marker=dict(colors=[PROFILE_COLORS.get(l, ACCENT_TEAL) for l in counts.index],
                    line=dict(color=DARK_BG, width=2)),
        textfont=dict(color=TEXT_COL),
        hole=0.4,
    ))
    fig.update_layout(title="Attacker Profile Distribution", **PLOTLY_DARK)
    return fig


def fig_top_countries(df: pd.DataFrame) -> go.Figure:
    if df.empty or "country" not in df.columns:
        return go.Figure().update_layout(**PLOTLY_DARK)

    top = df["country"].value_counts().head(10).reset_index()
    top.columns = ["country", "count"]
    fig = px.bar(top, x="count", y="country", orientation="h",
                 color="count",
                 color_continuous_scale=[[0, ACCENT_GREEN], [0.5, ACCENT_ORANGE], [1, ACCENT_RED]])
    fig.update_layout(title="Top 10 Attack-Source Countries",
                      coloraxis_showscale=False,
                      yaxis=dict(autorange="reversed", gridcolor=BORDER_COL, zerolinecolor=BORDER_COL),
                      xaxis=dict(gridcolor=BORDER_COL, zerolinecolor=BORDER_COL),
                      **PLOTLY_DARK)
    return fig


def fig_mitre_tactic_pie(df: pd.DataFrame) -> go.Figure:
    if df.empty or "mitre_tactic" not in df.columns:
        return go.Figure().update_layout(**PLOTLY_DARK)

    counts = df["mitre_tactic"].value_counts()
    colors = [ACCENT_TEAL, ACCENT_PURPLE, ACCENT_ORANGE, ACCENT_GREEN, ACCENT_RED, ACCENT_YELLOW]
    fig = go.Figure(go.Pie(
        labels=counts.index,
        values=counts.values,
        marker=dict(colors=colors[:len(counts)],
                    line=dict(color=DARK_BG, width=2)),
        textfont=dict(color=TEXT_COL),
        hole=0.35,
    ))
    fig.update_layout(title="MITRE ATT&CK Tactic Distribution", **PLOTLY_DARK)
    return fig


def fig_threat_score_histogram(df: pd.DataFrame) -> go.Figure:
    if df.empty or "threat_score" not in df.columns:
        return go.Figure().update_layout(**PLOTLY_DARK)

    fig = go.Figure()
    for profile, color in PROFILE_COLORS.items():
        subset = df[df["attacker_profile"] == profile]["threat_score"]
        fig.add_trace(go.Histogram(
            x=subset,
            name=profile,
            marker_color=color,
            opacity=0.75,
            nbinsx=20,
        ))
    fig.update_layout(
        title="Threat Score Distribution by Profile",
        barmode="overlay",
        xaxis_title="Threat Score (0-100)",
        yaxis_title="Count",
        **PLOTLY_DARK,
    )
    return fig


def fig_threat_score_scatter(df: pd.DataFrame) -> go.Figure:
    if df.empty or "threat_score" not in df.columns:
        return go.Figure().update_layout(**PLOTLY_DARK)

    fig = go.Figure()
    for profile, color in PROFILE_COLORS.items():
        sub = df[df["attacker_profile"] == profile]
        fig.add_trace(go.Scatter(
            x=sub["login_attempts"],
            y=sub["threat_score"],
            mode="markers",
            name=profile,
            marker=dict(color=color, size=6, opacity=0.7),
        ))
    fig.update_layout(
        title="Threat Score vs Login Attempts",
        xaxis_title="Login Attempts",
        yaxis_title="Threat Score",
        **PLOTLY_DARK,
    )
    return fig


# ── MITRE table helper ─────────────────────────────────────────────────────────

def mitre_table(df: pd.DataFrame):
    required = {"mitre_id", "mitre_technique", "mitre_tactic", "mitre_severity"}
    if df.empty or not required.issubset(df.columns):
        return html.P("MITRE data not available. Run: python main.py --mock --profile",
                      style={"color": ACCENT_ORANGE})

    cols = ["ip_address", "country", "attack_type",
            "mitre_id", "mitre_technique", "mitre_tactic", "mitre_severity",
            "threat_score", "attacker_profile"]
    available = [c for c in cols if c in df.columns]
    display = df[available].copy()

    # Severity sort order
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    if "mitre_severity" in display.columns:
        display["_sev_rank"] = display["mitre_severity"].map(sev_order).fillna(4)
        display = display.sort_values("_sev_rank").drop(columns=["_sev_rank"])

    col_defs = [{"name": c.replace("_", " ").title(), "id": c} for c in available]

    style_data_cond = []
    for severity, color in SEVERITY_COLORS.items():
        style_data_cond.append({
            "if": {"filter_query": f'{{mitre_severity}} = "{severity}"',
                   "column_id": "mitre_severity"},
            "backgroundColor": color,
            "color": DARK_BG,
            "fontWeight": "bold",
            "borderRadius": "4px",
        })

    return dash_table.DataTable(
        data=display.head(100).to_dict("records"),
        columns=col_defs,
        page_size=15,
        sort_action="native",
        filter_action="native",
        style_table={"overflowX": "auto"},
        style_header={
            "backgroundColor": DARK_BG,
            "color": ACCENT_TEAL,
            "fontWeight": "bold",
            "border": f"1px solid {BORDER_COL}",
            "fontFamily": "'JetBrains Mono', monospace",
        },
        style_cell={
            "backgroundColor": CARD_BG,
            "color": TEXT_COL,
            "border": f"1px solid {BORDER_COL}",
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "12px",
            "padding": "8px",
            "textAlign": "left",
            "maxWidth": "180px",
            "overflow": "hidden",
            "textOverflow": "ellipsis",
        },
        style_data_conditional=style_data_cond,
    )


# ── Geo map ────────────────────────────────────────────────────────────────────

def geo_tab_content():
    if os.path.exists(GEO_MAP_PATH):
        with open(GEO_MAP_PATH, "r", encoding="utf-8") as f:
            html_content = f.read()
        b64 = base64.b64encode(html_content.encode()).decode()
        src = f"data:text/html;base64,{b64}"
        return html.Iframe(src=src,
                           style={"width": "100%", "height": "600px",
                                  "border": f"1px solid {BORDER_COL}",
                                  "borderRadius": "8px"})
    else:
        return html.Div([
            html.P("Geo map not generated yet.", style={"color": ACCENT_ORANGE}),
            html.P("Run: python main.py --mock --profile --geo",
                   style={"color": MUTED_COL, "fontFamily": "monospace"}),
        ])


# ── App layout ─────────────────────────────────────────────────────────────────

def build_layout(df: pd.DataFrame) -> html.Div:
    total      = len(df)
    targeted   = int((df["attacker_profile"] == "Targeted Attacker").sum()) if not df.empty else 0
    critical   = int((df.get("mitre_severity", pd.Series()) == "Critical").sum()) if not df.empty else 0
    avg_threat = round(df["threat_score"].mean(), 1) if ("threat_score" in df.columns and not df.empty) else 0

    kpi_style = dict(textAlign="center", flex="1", padding="20px",
                     background=CARD_BG, border=f"1px solid {BORDER_COL}",
                     borderRadius="8px", margin="0 8px")
    kpi_num   = dict(fontSize="36px", fontWeight="bold", color=ACCENT_TEAL,
                     fontFamily="'JetBrains Mono', monospace")
    kpi_label = dict(fontSize="12px", color=MUTED_COL, marginTop="4px",
                     textTransform="uppercase", letterSpacing="1px")

    return html.Div(style={"background": DARK_BG, "minHeight": "100vh",
                           "fontFamily": "'JetBrains Mono', 'Fira Code', monospace",
                           "color": TEXT_COL, "padding": "24px"}, children=[

        # ── Header ──────────────────────────────────────────────────────────
        html.Div(style={"marginBottom": "24px"}, children=[
            html.H1("🛡 Honeypot Attacker Profiling System",
                    style={"color": ACCENT_TEAL, "margin": 0,
                           "fontSize": "24px", "fontWeight": "700"}),
            
        ]),

        # ── KPI row ──────────────────────────────────────────────────────────
        html.Div(style={"display": "flex", "marginBottom": "24px"}, children=[
            html.Div([html.Div(str(total),     style=kpi_num),
                      html.Div("Total Events", style=kpi_label)], style=kpi_style),
            html.Div([html.Div(str(targeted),         style={**kpi_num, "color": ACCENT_RED}),
                      html.Div("Targeted Attackers",  style=kpi_label)], style=kpi_style),
            html.Div([html.Div(str(critical),         style={**kpi_num, "color": ACCENT_ORANGE}),
                      html.Div("Critical MITRE Hits", style=kpi_label)], style=kpi_style),
            html.Div([html.Div(str(avg_threat),       style={**kpi_num, "color": ACCENT_YELLOW}),
                      html.Div("Avg Threat Score",    style=kpi_label)], style=kpi_style),
        ]),

        # ── Tabs ─────────────────────────────────────────────────────────────
        dcc.Tabs(id="tabs", value="tab-overview",
                 style={"marginBottom": "20px"},
                 colors={"border": BORDER_COL, "primary": ACCENT_TEAL, "background": DARK_BG},
                 children=[
            dcc.Tab(label="📊 Overview",      value="tab-overview",
                    style={"color": MUTED_COL, "backgroundColor": CARD_BG},
                    selected_style={"color": ACCENT_TEAL, "backgroundColor": DARK_BG,
                                    "borderTop": f"2px solid {ACCENT_TEAL}"}),
            dcc.Tab(label="🎯 MITRE ATT&CK",  value="tab-mitre",
                    style={"color": MUTED_COL, "backgroundColor": CARD_BG},
                    selected_style={"color": ACCENT_TEAL, "backgroundColor": DARK_BG,
                                    "borderTop": f"2px solid {ACCENT_TEAL}"}),
            dcc.Tab(label="🌍 Geo Map",        value="tab-geo",
                    style={"color": MUTED_COL, "backgroundColor": CARD_BG},
                    selected_style={"color": ACCENT_TEAL, "backgroundColor": DARK_BG,
                                    "borderTop": f"2px solid {ACCENT_TEAL}"}),
            dcc.Tab(label="⚠️ Threat Scores", value="tab-threat",
                    style={"color": MUTED_COL, "backgroundColor": CARD_BG},
                    selected_style={"color": ACCENT_TEAL, "backgroundColor": DARK_BG,
                                    "borderTop": f"2px solid {ACCENT_TEAL}"}),
        ]),

        html.Div(id="tab-content"),
    ])


# ── Tab content renderer ───────────────────────────────────────────────────────

def render_overview(df):
    return html.Div([
        html.Div(style={"display": "grid",
                         "gridTemplateColumns": "1fr 1fr",
                         "gap": "16px"}, children=[
            card(dcc.Graph(figure=fig_attack_frequency(df), config={"displayModeBar": False})),
            card(dcc.Graph(figure=fig_profile_pie(df),      config={"displayModeBar": False})),
            card(dcc.Graph(figure=fig_top_countries(df),    config={"displayModeBar": False})),
            card(html.Div([
                html.H3("📡 Threat Feed", style={"color": ACCENT_TEAL, "marginTop": 0,
                                                  "fontSize": "14px", "letterSpacing": "1px"}),
                mitre_table(df),
            ])),
        ]),
    ])


def render_mitre(df):
    return html.Div([
        card(html.Div([
            html.H3("🎯 MITRE ATT&CK Threat Feed",
                    style={"color": ACCENT_TEAL, "marginTop": 0, "fontSize": "16px"}),
            html.P("Severity: Critical=Red · High=Orange · Medium=Yellow · Low=Green",
                   style={"color": MUTED_COL, "fontSize": "12px"}),
            mitre_table(df),
        ])),
        card(dcc.Graph(figure=fig_mitre_tactic_pie(df), config={"displayModeBar": False})),
    ])


def render_geo():
    return card(geo_tab_content())


def render_threat(df):
    return html.Div([
        html.Div(style={"display": "grid", "gridTemplateColumns": "1fr 1fr", "gap": "16px"},
                 children=[
            card(dcc.Graph(figure=fig_threat_score_histogram(df), config={"displayModeBar": False})),
            card(dcc.Graph(figure=fig_threat_score_scatter(df),   config={"displayModeBar": False})),
        ]),
    ])


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> dash.Dash:
    df = load_profiles()

    app = dash.Dash(__name__, title="Honeypot Profiler")
    app.layout = build_layout(df)

    @app.callback(Output("tab-content", "children"),
                  Input("tabs", "value"))
    def render_tab(tab):
        _df = load_profiles()   # fresh read on each tab switch
        if tab == "tab-overview":
            return render_overview(_df)
        elif tab == "tab-mitre":
            return render_mitre(_df)
        elif tab == "tab-geo":
            return render_geo()
        elif tab == "tab-threat":
            return render_threat(_df)
        return html.P("Unknown tab")

    return app


def run_dashboard(debug: bool = False, port: int = 8050):
    app = create_app()
    print(f"[dashboard] Starting at http://127.0.0.1:{port}")
    app.run(debug=debug, port=port)


# Create the Dash application for Gunicorn/Render
app = create_app()
server = app.server


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )