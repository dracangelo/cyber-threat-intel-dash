import dash
from dash import dcc, html, Input, Output, State, callback_context
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import io
import csv
from typing import Optional
import uuid
import csv
import io
from data_aggregator import ThreatDataAggregator
from flask import jsonify

# Initialize the Dash app with a modern theme
app = dash.Dash(__name__, 
    external_stylesheets=[
        dbc.themes.CYBORG,
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css'
    ],
    suppress_callback_exceptions=True
)
app.title = "Cyber Threat Intelligence Dashboard"

# API Routes
@app.server.route('/api/threat/<indicator_type>/<path:value>')
def api_threat(indicator_type, value):
    result = aggregator.search_indicators(value, indicator_type)
    return jsonify(result)

# Initialize data aggregator
aggregator = ThreatDataAggregator()

# Minimal ISO-2 to ISO-3 mapping for map visualization
ISO2_TO_ISO3 = {
    "US": "USA", "GB": "GBR", "DE": "DEU", "FR": "FRA", "CN": "CHN", "RU": "RUS",
    "IN": "IND", "BR": "BRA", "CA": "CAN", "AU": "AUS", "JP": "JPN", "KR": "KOR",
    "ZA": "ZAF", "NG": "NGA", "KE": "KEN", "EG": "EGY", "TR": "TUR", "UA": "UKR",
    "PL": "POL", "ES": "ESP", "IT": "ITA", "NL": "NLD", "SE": "SWE", "NO": "NOR",
    "FI": "FIN", "DK": "DNK", "BE": "BEL", "CH": "CHE", "AT": "AUT", "MX": "MEX",
    "AR": "ARG", "CL": "CHL", "CO": "COL", "PE": "PER", "VE": "VEN", "SA": "SAU",
    "AE": "ARE", "IL": "ISR", "IR": "IRN", "PK": "PAK", "BD": "BGD", "ID": "IDN",
    "PH": "PHL", "VN": "VNM", "TH": "THA", "MY": "MYS", "SG": "SGP", "NZ": "NZL",
    "CZ": "CZE", "RO": "ROU", "HU": "HUN", "GR": "GRC", "PT": "PRT", "IE": "IRL"
}

def _iso2_to_iso3(code: str) -> Optional[str]:
    if not code:
        return None
    return ISO2_TO_ISO3.get(code.upper())

# Define the modern layout
app.layout = dbc.Container([
    # Modern Header with gradient
    dbc.Row([
        dbc.Col([
            html.Div([
                html.Div([
                    html.I(className="fas fa-shield-alt me-3", style={"fontSize": "2rem", "color": "#00ff88"}),
                    html.H1("Cyber Threat Intelligence Dashboard", 
                           className="mb-0", 
                           style={"color": "#ffffff", "fontWeight": "300", "letterSpacing": "1px"}),
                    html.P("Real-time threat intelligence from multiple sources", 
                          className="mb-0 mt-2", 
                          style={"color": "#a0a0a0", "fontSize": "1.1rem"})
                ], className="text-center")
            ], className="py-4", style={
                "background": "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                "borderRadius": "15px",
                "marginBottom": "2rem",
                "boxShadow": "0 10px 30px rgba(0,0,0,0.3)"
            })
        ])
    ]),
    
    # Auto-refresh and status bar
    dbc.Row([
        dbc.Col([
            html.Div([
                dcc.Interval(
                    id='interval-component',
                    interval=30000,  # 30 seconds
                    n_intervals=0
                ),
                html.Div(id='last-update', className="text-muted small")
            ], className="d-flex justify-content-between align-items-center p-3", 
            style={"background": "rgba(255,255,255,0.05)", "borderRadius": "10px"})
        ])
    ], className="mb-4"),
    
    # Alert Section with modern styling
    dbc.Row([
        dbc.Col([
            html.Div(id='alerts-container')
        ], width=12)
    ], className="mb-4"),
    
    # Enhanced Metrics Cards
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-chart-line me-2", style={"color": "#00ff88", "fontSize": "1.5rem"}),
                        html.H6("Total Threats", className="card-title mb-2", style={"color": "#a0a0a0", "fontWeight": "400"}),
                        html.H2(id="total-threats", className="mb-0", style={"color": "#ffffff", "fontWeight": "700"}),
                        html.Small("↑ 12% from last hour", className="text-success", id="total-threats-trend")
                    ])
                ], className="text-center")
            ], className="h-100 border-0", style={
                "background": "linear-gradient(135deg, rgba(0,255,136,0.1) 0%, rgba(0,255,136,0.05) 100%)",
                "border": "1px solid rgba(0,255,136,0.3)",
                "borderRadius": "15px",
                "transition": "all 0.3s ease"
            })
        ], width=3, className="mb-3"),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-exclamation-triangle me-2", style={"color": "#ff6b6b", "fontSize": "1.5rem"}),
                        html.H6("High Risk", className="card-title mb-2", style={"color": "#a0a0a0", "fontWeight": "400"}),
                        html.H2(id="high-risk-indicators", className="mb-0", style={"color": "#ffffff", "fontWeight": "700"}),
                        html.Small("↑ 5% from last hour", className="text-danger", id="high-risk-trend")
                    ])
                ], className="text-center")
            ], className="h-100 border-0", style={
                "background": "linear-gradient(135deg, rgba(255,107,107,0.1) 0%, rgba(255,107,107,0.05) 100%)",
                "border": "1px solid rgba(255,107,107,0.3)",
                "borderRadius": "15px",
                "transition": "all 0.3s ease"
            })
        ], width=3, className="mb-3"),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-fire me-2", style={"color": "#ffd93d", "fontSize": "1.5rem"}),
                        html.H6("Active Campaigns", className="card-title mb-2", style={"color": "#a0a0a0", "fontWeight": "400"}),
                        html.H2(id="active-campaigns", className="mb-0", style={"color": "#ffffff", "fontWeight": "700"}),
                        html.Small("↓ 2% from last hour", className="text-warning", id="campaigns-trend")
                    ])
                ], className="text-center")
            ], className="h-100 border-0", style={
                "background": "linear-gradient(135deg, rgba(255,217,61,0.1) 0%, rgba(255,217,61,0.05) 100%)",
                "border": "1px solid rgba(255,217,61,0.3)",
                "borderRadius": "15px",
                "transition": "all 0.3s ease"
            })
        ], width=3, className="mb-3"),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-database me-2", style={"color": "#6bcf7f", "fontSize": "1.5rem"}),
                        html.H6("Data Sources", className="card-title mb-2", style={"color": "#a0a0a0", "fontWeight": "400"}),
                        html.H2(id="data-sources", className="mb-0", style={"color": "#ffffff", "fontWeight": "700"}),
                        html.Small("All connected", className="text-success", id="sources-status")
                    ])
                ], className="text-center")
            ], className="h-100 border-0", style={
                "background": "linear-gradient(135deg, rgba(107,207,127,0.1) 0%, rgba(107,207,127,0.05) 100%)",
                "border": "1px solid rgba(107,207,127,0.3)",
                "borderRadius": "15px",
                "transition": "all 0.3s ease"
            })
        ], width=3, className="mb-3")
    ], className="mb-4"),

    # Risk and Health Row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-shield-virus me-2", style={"color": "#ff6b6b", "fontSize": "1.5rem"}),
                        html.H6("Risk Score", className="card-title mb-2", style={"color": "#a0a0a0", "fontWeight": "400"}),
                        html.H2(id="risk-score", className="mb-0", style={"color": "#ffffff", "fontWeight": "700"}),
                        html.Small(id="risk-severity", className="text-warning")
                    ])
                ], className="text-center")
            ], className="h-100 border-0", style={
                "background": "linear-gradient(135deg, rgba(255,107,107,0.12) 0%, rgba(255,107,107,0.05) 100%)",
                "border": "1px solid rgba(255,107,107,0.3)",
                "borderRadius": "15px"
            })
        ], width=6, className="mb-3"),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-heartbeat me-2", style={"color": "#ffd93d", "fontSize": "1.5rem"}),
                        html.H6("Feed Health", className="card-title mb-2", style={"color": "#a0a0a0", "fontWeight": "400"}),
                        html.H2(id="health-summary", className="mb-0", style={"color": "#ffffff", "fontWeight": "700"}),
                        html.Small(id="health-subtitle", className="text-muted")
                    ])
                ], className="text-center")
            ], className="h-100 border-0", style={
                "background": "linear-gradient(135deg, rgba(255,217,61,0.12) 0%, rgba(255,217,61,0.05) 100%)",
                "border": "1px solid rgba(255,217,61,0.3)",
                "borderRadius": "15px"
            })
        ], width=6, className="mb-3")
    ], className="mb-4"),
    
    # Enhanced Charts Row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Threat Distribution", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-chart-pie ms-2", style={"color": "#00ff88"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    dcc.Graph(id="source-chart", config={"displayModeBar": False})
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ], width=6, className="mb-4"),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Trending Threats", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-fire ms-2", style={"color": "#ff6b6b"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    dcc.Graph(id="trending-chart", config={"displayModeBar": False})
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ], width=6, className="mb-4")
    ]),
    
    # Timeline and Categories Row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("7-Day Threat Timeline", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-clock ms-2", style={"color": "#6bcf7f"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    dcc.Graph(id="timeline-chart", config={"displayModeBar": False})
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ], width=8, className="mb-4"),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Threat Categories", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-tags ms-2", style={"color": "#ffd93d"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    dcc.Graph(id="categories-chart", config={"displayModeBar": False})
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ], width=4, className="mb-4")
    ]),
    
    # Global Threat Map Row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Global Threat Map", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-globe ms-2", style={"color": "#6bcf7f"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    dcc.Graph(id="threat-map", config={"displayModeBar": False})
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ])
    ], className="mb-4"),

    # Global Attack Map and Historical Trends
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Global Attack Map", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-globe-africa ms-2", style={"color": "#00ff88"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    dcc.Graph(id="attack-map", config={"displayModeBar": False})
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ], width=7, className="mb-4"),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Historical Threat Trends", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-wave-square ms-2", style={"color": "#ffd93d"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    dcc.Graph(id="history-chart", config={"displayModeBar": False})
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ], width=5, className="mb-4")
    ]),
    
    # Enhanced Search Section
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Threat Intelligence Search", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-search ms-2", style={"color": "#00ff88"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            dbc.InputGroup([
                                dbc.Input(
                                    id="search-input",
                                    placeholder="Search IP, domain, URL, or hash...",
                                    type="text",
                                    style={"borderRadius": "10px 0 0 10px"}
                                ),
                                dbc.Select(
                                    id="search-type",
                                    options=[
                                        {"label": "All", "value": "all"},
                                        {"label": "IP", "value": "ip"},
                                        {"label": "Domain", "value": "domain"},
                                        {"label": "URL", "value": "url"},
                                        {"label": "Hash", "value": "hash"}
                                    ],
                                    value="all",
                                    style={"borderRadius": "0 10px 10px 0"}
                                )
                            ])
                        ], width=8),
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fas fa-search me-2"),
                                "Search"
                            ], id="search-button", color="primary", className="w-100", 
                            style={"borderRadius": "10px", "fontWeight": "500"})
                        ], width=2),
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fas fa-sync-alt me-2"),
                                "Clear"
                            ], id="clear-button", color="secondary", className="w-100", 
                            style={"borderRadius": "10px", "fontWeight": "500"})
                        ], width=2)
                    ]),
                    html.Div(id="search-results", className="mt-4")
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ])
    ], className="mb-4"),
    
    # Top Risk Indicators Section
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.H5("Top Risk Indicators", className="mb-0", style={"color": "#ffffff"}),
                        html.I(className="fas fa-exclamation-triangle ms-2", style={"color": "#ff6b6b"})
                    ], className="d-flex align-items-center"),
                    html.Div([
                        dbc.Button("Export JSON", id="export-json-btn", color="secondary", size="sm", className="ms-2"),
                        dbc.Button("Export CSV", id="export-csv-btn", color="secondary", size="sm", className="ms-2")
                    ], className="d-flex")
                ], className="border-0 bg-transparent d-flex justify-content-between align-items-center"),
                dbc.CardBody([
                    html.Div(id="top-risk-indicators")
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ])
    ], className="mb-4"),

    # Export and Top Lists
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("IOC Export", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-file-export ms-2", style={"color": "#6bcf7f"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([dbc.Button("Export JSON", id="export-json", color="secondary", className="w-100")], width=4),
                        dbc.Col([dbc.Button("Export CSV", id="export-csv", color="secondary", className="w-100")], width=4),
                        dbc.Col([dbc.Button("Export STIX", id="export-stix", color="secondary", className="w-100")], width=4)
                    ]),
                    dcc.Download(id="download-ioc")
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ])
    ], className="mb-4"),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Top Threat Lists", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-list-ol ms-2", style={"color": "#00ff88"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    html.Div(id="top-lists")
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ], width=6, className="mb-4"),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Feed Health Details", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-heartbeat ms-2", style={"color": "#ffd93d"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    html.Div(id="feed-health")
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ], width=6, className="mb-4")
    ]),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Threat Campaign Tags", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-tags ms-2", style={"color": "#ff6b6b"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    html.Div(id="campaign-tags")
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ])
    ], className="mb-4"),
    
    # Enhanced Source Status
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5("Data Source Status", className="mb-0", style={"color": "#ffffff"}),
                    html.I(className="fas fa-network-wired ms-2", style={"color": "#6bcf7f"})
                ], className="border-0 bg-transparent"),
                dbc.CardBody([
                    html.Div(id="source-status")
                ])
            ], className="border-0", style={"background": "rgba(255,255,255,0.02)", "borderRadius": "15px"})
        ])
    ]),
    
    # Store component
    dcc.Store(id='threat-data-store'),
    dcc.Download(id="download")
    
], fluid=True, style={"padding": "2rem", "backgroundColor": "#0a0a0a"})

# Add external CSS for animations
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
        .card {
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.2);
        }
        .btn {
            transition: all 0.3s ease;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        .pulse {
            animation: pulse 2s infinite;
        }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

# Callback to update data
@app.callback(
    [Output('threat-data-store', 'data'),
     Output('last-update', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_data(n):
    data = aggregator.get_aggregated_threat_data()
    last_update = f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    return data, last_update

# Callback to update metrics
@app.callback(
    [Output('total-threats', 'children'),
     Output('high-risk-indicators', 'children'),
     Output('active-campaigns', 'children'),
     Output('data-sources', 'children')],
    [Input('threat-data-store', 'data')]
)
def update_metrics(data):
    if not data:
        return "0", "0", "0", "0"
    
    summary = data.get('summary', {})
    sources_count = len([s for s in data.get('sources', {}).values() if 'error' not in s])
    
    return (
        str(summary.get('total_threats', 0)),
        str(summary.get('high_risk_indicators', 0)),
        str(summary.get('active_campaigns', 0)),
        str(sources_count)
    )

# Callback to update risk and health summary
@app.callback(
    [Output('risk-score', 'children'),
     Output('risk-severity', 'children'),
     Output('health-summary', 'children'),
     Output('health-subtitle', 'children')],
    [Input('threat-data-store', 'data')]
)
def update_risk_and_health(data):
    if not data:
        return "0", "Low", "0/0", "No feeds configured"
    risk = data.get("risk", {})
    score = risk.get("score", 0)
    severity = risk.get("severity", "Low")
    health = data.get("health", {})
    online = len([h for h in health.values() if h.get("online") is True])
    total = len(health)
    subtitle = "All feeds healthy" if total > 0 and online == total else "Degraded or offline feeds"
    return str(score), severity, f"{online}/{total}", subtitle

# Callback to update alerts
@app.callback(
    Output('alerts-container', 'children'),
    [Input('threat-data-store', 'data')]
)
def update_alerts(data):
    if not data or not data.get('alerts'):
        return dbc.Alert([
            html.I(className="fas fa-check-circle me-2"),
            "No active threats detected"
        ], color="success", className="mb-3")
    
    alerts = data['alerts']
    alert_cards = []
    
    for i, alert in enumerate(alerts[:5]):  # Show top 5 alerts
        color_map = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'secondary'
        }
        
        icon_map = {
            'critical': 'fas fa-exclamation-triangle',
            'high': 'fas fa-exclamation-circle',
            'medium': 'fas fa-info-circle',
            'low': 'fas fa-minus-circle'
        }
        
        alert_cards.append(
            dbc.Alert([
                html.Div([
                    html.Div([
                        html.I(className=f"{icon_map.get(alert['level'], 'fas fa-info-circle')} me-2", 
                              style={"fontSize": "1.2rem"}),
                        html.Strong(f"{alert['level'].upper()}: "),
                        html.Span(alert['message'], style={"fontWeight": "500"})
                    ], className="mb-2"),
                    html.Div([
                        html.Small([
                            html.I(className="fas fa-database me-1"),
                            f"Source: {alert['source']} | ",
                            html.I(className="fas fa-clock me-1"),
                            alert['timestamp'][:19].replace('T', ' ')
                        ], className="text-muted")
                    ])
                ], className="d-flex justify-content-between align-items-start")
            ], color=color_map.get(alert['level'], 'secondary'), 
               className="mb-3 border-0",
               style={
                   "borderRadius": "10px",
                   "borderLeft": f"4px solid {color_map.get(alert['level'], '#6c757d')}",
                   "background": f"rgba({color_map.get(alert['level'], '#6c757d')}, 0.1)"
               })
        )
    
    return alert_cards

# Callback to update source chart
@app.callback(
    Output('source-chart', 'figure'),
    [Input('threat-data-store', 'data')]
)
def update_source_chart(data):
    if not data:
        return go.Figure()
    
    sources = data.get('sources', {})
    source_names = []
    threat_counts = []
    
    for source_name, source_data in sources.items():
        if 'error' not in source_data:
            if source_name == 'abuseipdb':
                source_names.append('AbuseIPDB')
                threat_counts.append(source_data.get('total_reports', 0))
            elif source_name == 'alienvault':
                source_names.append('AlienVault OTX')
                threat_counts.append(source_data.get('total_pulses', 0))
            elif source_name == 'virustotal':
                source_names.append('VirusTotal')
                vt_data = source_data.get('scan_distribution', {})
                threat_counts.append(vt_data.get('malicious', 0) + vt_data.get('suspicious', 0))
    
    if not source_names:
        return go.Figure()
    
    fig = go.Figure(data=[go.Pie(
        labels=source_names,
        values=threat_counts,
        hole=0.6,
        marker=dict(colors=['#00ff88', '#ff6b6b', '#ffd93d']),
        textinfo='label+percent',
        textfont=dict(size=12, color='#ffffff'),
        hovertemplate='<b>%{label}</b><br>Threats: %{value}<br>Percentage: %{percent}<extra></extra>'
    )])
    
    fig.update_layout(
        title={
            'text': 'Threat Distribution',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 16, 'color': '#ffffff'}
        },
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff'),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(color='#ffffff')
        ),
        margin=dict(t=50, b=50, l=50, r=50)
    )
    
    return fig

# Callback to update trending chart
@app.callback(
    Output('trending-chart', 'figure'),
    [Input('threat-data-store', 'data')]
)
def update_trending_chart(data):
    if not data:
        return go.Figure()
    
    trending = data.get('summary', {}).get('trending_threats', [])
    
    if not trending:
        return go.Figure()
    
    names = [item['name'] for item in trending[:10]]
    counts = [item['count'] for item in trending[:10]]
    sources = [item['source'] for item in trending[:10]]
    
    # Define colors for different sources
    color_map = {
        'abuseipdb': '#00ff88',
        'alienvault': '#ff6b6b',
        'virustotal': '#ffd93d'
    }
    colors = [color_map.get(source, '#6bcf7f') for source in sources]
    
    fig = go.Figure(data=[go.Bar(
        x=counts,
        y=names,
        orientation='h',
        marker=dict(
            color=colors,
            line=dict(color='#ffffff', width=1)
        ),
        text=counts,
        textposition='auto',
        textfont=dict(color='#ffffff', size=10),
        hovertemplate='<b>%{y}</b><br>Count: %{x}<br>Source: %{customdata}<extra></extra>',
        customdata=sources
    )])
    
    fig.update_layout(
        title={
            'text': 'Top Trending Threats',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 16, 'color': '#ffffff'}
        },
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff'),
        xaxis=dict(
            title='Count',
            color='#ffffff',
            gridcolor='rgba(255,255,255,0.1)',
            tickfont=dict(color='#ffffff')
        ),
        yaxis=dict(
            title='',
            color='#ffffff',
            gridcolor='rgba(255,255,255,0.1)',
            tickfont=dict(color='#ffffff'),
            categoryorder='total ascending'
        ),
        margin=dict(t=50, b=50, l=150, r=50),
        height=400
    )
    
    return fig

# Callback to update timeline chart
@app.callback(
    Output('timeline-chart', 'figure'),
    [Input('threat-data-store', 'data')]
)
def update_timeline_chart(data):
    if not data:
        return go.Figure()
    
    # Get timeline data
    timeline_data = aggregator.get_threat_timeline(7)
    
    dates = list(timeline_data.keys())
    abuse_reports = [timeline_data[date]['abuse_reports'] for date in dates]
    otx_pulses = [timeline_data[date]['otx_pulses'] for date in dates]
    vt_detections = [timeline_data[date]['vt_detections'] for date in dates]
    
    fig = go.Figure()
    
    # Add traces with modern styling
    fig.add_trace(go.Scatter(
        x=dates,
        y=abuse_reports,
        mode='lines+markers',
        name='AbuseIPDB Reports',
        line=dict(color='#00ff88', width=3),
        marker=dict(size=8, color='#00ff88', line=dict(color='#ffffff', width=2)),
        hovertemplate='<b>%{fullData.name}</b><br>Date: %{x}<br>Count: %{y}<extra></extra>'
    ))
    
    fig.add_trace(go.Scatter(
        x=dates,
        y=otx_pulses,
        mode='lines+markers',
        name='OTX Pulses',
        line=dict(color='#ff6b6b', width=3),
        marker=dict(size=8, color='#ff6b6b', line=dict(color='#ffffff', width=2)),
        hovertemplate='<b>%{fullData.name}</b><br>Date: %{x}<br>Count: %{y}<extra></extra>'
    ))
    
    fig.add_trace(go.Scatter(
        x=dates,
        y=vt_detections,
        mode='lines+markers',
        name='VirusTotal Detections',
        line=dict(color='#ffd93d', width=3),
        marker=dict(size=8, color='#ffd93d', line=dict(color='#ffffff', width=2)),
        hovertemplate='<b>%{fullData.name}</b><br>Date: %{x}<br>Count: %{y}<extra></extra>'
    ))
    
    fig.update_layout(
        title={
            'text': '7-Day Threat Timeline',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 16, 'color': '#ffffff'}
        },
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff'),
        xaxis=dict(
            title='Date',
            color='#ffffff',
            gridcolor='rgba(255,255,255,0.1)',
            tickfont=dict(color='#ffffff'),
            showgrid=True
        ),
        yaxis=dict(
            title='Count',
            color='#ffffff',
            gridcolor='rgba(255,255,255,0.1)',
            tickfont=dict(color='#ffffff'),
            showgrid=True
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(color='#ffffff')
        ),
        margin=dict(t=50, b=50, l=50, r=50),
        height=350
    )
    
    return fig

# Callback to update categories chart
@app.callback(
    Output('categories-chart', 'figure'),
    [Input('threat-data-store', 'data')]
)
def update_categories_chart(data):
    if not data:
        return go.Figure()
    
    # Extract categories from AbuseIPDB data
    sources = data.get('sources', {})
    categories = {}
    
    if 'abuseipdb' in sources and 'error' not in sources['abuseipdb']:
        abuse_categories = sources['abuseipdb'].get('top_categories', {})
        categories.update(abuse_categories)
    
    if not categories:
        return go.Figure()
    
    # Take top 8 categories
    sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:8]
    cat_names = [str(cat[0]) for cat in sorted_cats]
    cat_counts = [cat[1] for cat in sorted_cats]
    
    fig = go.Figure(data=[go.Bar(
        x=cat_names,
        y=cat_counts,
        marker=dict(
            color='#00ff88',
            line=dict(color='#ffffff', width=1)
        ),
        text=cat_counts,
        textposition='auto',
        textfont=dict(color='#ffffff', size=10),
        hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>'
    )])
    
    fig.update_layout(
        title={
            'text': 'Top Threat Categories',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 16, 'color': '#ffffff'}
        },
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff'),
        xaxis=dict(
            title='',
            color='#ffffff',
            gridcolor='rgba(255,255,255,0.1)',
            tickfont=dict(color='#ffffff', size=10),
            tickangle=45
        ),
        yaxis=dict(
            title='Count',
            color='#ffffff',
            gridcolor='rgba(255,255,255,0.1)',
            tickfont=dict(color='#ffffff')
        ),
        margin=dict(t=50, b=80, l=50, r=50),
        height=350
    )
    
    return fig

# Callback to update attack map
@app.callback(
    Output('attack-map', 'figure'),
    [Input('threat-data-store', 'data')]
)
def update_attack_map(data):
    if not data:
        return go.Figure()
    country_counts = data.get("geo", {}).get("by_country", {})
    locations = []
    values = []
    for iso2, count in country_counts.items():
        iso3 = _iso2_to_iso3(iso2)
        if iso3:
            locations.append(iso3)
            values.append(count)
    if not locations:
        return go.Figure()
    fig = px.choropleth(
        locations=locations,
        color=values,
        locationmode="ISO-3",
        color_continuous_scale="Reds"
    )
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff'),
        margin=dict(t=20, b=20, l=20, r=20),
        coloraxis_colorbar=dict(title="Threats")
    )
    return fig

# Callback to update historical trends chart
@app.callback(
    Output('history-chart', 'figure'),
    [Input('threat-data-store', 'data')]
)
def update_history_chart(data):
    history = aggregator.get_history(7)
    if not history:
        return go.Figure()
    dates = [h.get("timestamp", "")[:10] for h in history]
    total = [h.get("total_threats", 0) for h in history]
    high_risk = [h.get("high_risk_indicators", 0) for h in history]
    campaigns = [h.get("active_campaigns", 0) for h in history]
    risk_score = [h.get("risk_score", 0) for h in history]

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=dates, y=total, mode='lines+markers', name='Total Threats', line=dict(color='#00ff88')))
    fig.add_trace(go.Scatter(x=dates, y=high_risk, mode='lines+markers', name='High Risk', line=dict(color='#ff6b6b')))
    fig.add_trace(go.Scatter(x=dates, y=campaigns, mode='lines+markers', name='Campaigns', line=dict(color='#ffd93d')))
    fig.add_trace(go.Scatter(x=dates, y=risk_score, mode='lines+markers', name='Risk Score', line=dict(color='#6bcf7f')))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff'),
        margin=dict(t=20, b=20, l=20, r=20),
        height=300,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(color='#ffffff'))
    )
    return fig

# Callback to update top lists
@app.callback(
    Output('top-lists', 'children'),
    [Input('threat-data-store', 'data')]
)
def update_top_lists(data):
    if not data:
        return ""
    top_lists = data.get("top_lists", {})
    sections = []
    label_map = {
        "ip": "Top Malicious IPs",
        "domain": "Top Malicious Domains",
        "url": "Top Malicious URLs",
        "hash": "Top Malware Hashes"
    }
    for key, label in label_map.items():
        items = top_lists.get(key, [])
        if not items:
            list_items = [html.Li("No data available", className="text-muted")]
        else:
            list_items = [
                html.Li(f"{item.get('value')} (Score: {item.get('score')}, Sources: {item.get('correlation_count')})")
                for item in items
            ]
        sections.append(html.Div([
            html.H6(label, className="text-white"),
            html.Ul(list_items)
        ], className="mb-3"))
    return sections

# Callback to update feed health table
@app.callback(
    Output('feed-health', 'children'),
    [Input('threat-data-store', 'data')]
)
def update_feed_health(data):
    if not data:
        return ""
    health = data.get("health", {})
    rows = []
    for source, info in health.items():
        status = "Online" if info.get("online") else "Offline"
        latency = info.get("response_ms")
        latency_text = f"{latency} ms" if isinstance(latency, int) else "N/A"
        rows.append(html.Tr([
            html.Td(source.title()),
            html.Td(status),
            html.Td(latency_text),
            html.Td(info.get("warning") or info.get("error") or "-")
        ]))
    return dbc.Table([
        html.Thead(html.Tr([html.Th("Feed"), html.Th("Status"), html.Th("Latency"), html.Th("Notes")])),
        html.Tbody(rows)
    ], bordered=False, hover=True, responsive=True, className="text-white")

# Callback to update campaign tags
@app.callback(
    Output('campaign-tags', 'children'),
    [Input('threat-data-store', 'data')]
)
def update_campaign_tags(data):
    if not data:
        return ""
    campaigns = data.get("campaigns", {})
    tags = campaigns.get("top_tags", {})
    authors = campaigns.get("top_authors", {})
    recent = campaigns.get("recent_pulses", [])

    tag_list = [html.Li(f"{tag} ({count})") for tag, count in tags.items()] or [html.Li("No tags available", className="text-muted")]
    author_list = [html.Li(f"{author} ({count})") for author, count in authors.items()] or [html.Li("No authors available", className="text-muted")]
    recent_list = [html.Li(f"{p.get('name')} ({p.get('indicators')} indicators)") for p in recent] or [html.Li("No recent pulses", className="text-muted")]

    return html.Div([
        html.Div([html.H6("Top Tags", className="text-white"), html.Ul(tag_list)], className="mb-3"),
        html.Div([html.H6("Top Authors", className="text-white"), html.Ul(author_list)], className="mb-3"),
        html.Div([html.H6("Recent Pulses", className="text-white"), html.Ul(recent_list)], className="mb-3")
    ])

# Callback for search functionality
@app.callback(
    [Output('search-results', 'children'),
     Output('search-input', 'value')],
    [Input('search-button', 'n_clicks'),
     Input('clear-button', 'n_clicks')],
    [State('search-input', 'value'),
     State('search-type', 'value')],
    prevent_initial_call=True
)
def perform_search(search_clicks, clear_clicks, query, search_type):
    ctx = callback_context
    if not ctx.triggered:
        return "", dash.no_update
    
    triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if triggered_id == 'clear-button':
        return "", ""
    
    if not query:
        return dbc.Alert([
            html.I(className="fas fa-info-circle me-2"),
            "Please enter a search term"
        ], color="info", className="mb-3"), dash.no_update
    
    try:
        results = aggregator.search_indicators(query, search_type)
        
        result_cards = []

        risk = results.get("risk", {})
        result_cards.append(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-shield-virus me-2", style={"color": "#ff6b6b", "fontSize": "1.2rem"}),
                        html.Strong("IOC Risk Score: "),
                        html.Span(f"{risk.get('score', 0)} ({risk.get('severity', 'Low')})", className="text-muted")
                    ])
                ])
            ], className="mb-3 border-0", style={"background": "rgba(255,107,107,0.08)", "borderRadius": "10px"})
        )
        
        for source, data in results.get('results', {}).items():
            if 'error' in data:
                result_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fas fa-exclamation-triangle me-2", 
                                      style={"color": "#ff6b6b", "fontSize": "1.2rem"}),
                                html.Strong(f"{source.title()}: "),
                                html.Span("Error retrieving data", className="text-muted")
                            ])
                        ])
                    ], className="mb-3 border-0", 
                       style={"background": "rgba(255,107,107,0.1)", "borderRadius": "10px"})
                )
            else:
                # Parse and display results based on source
                if source == 'abuseipdb' and 'data' in data:
                    abuse_data = data['data']
                    result_cards.append(
                        dbc.Card([
                            dbc.CardHeader([
                                html.H6([
                                    html.I(className="fas fa-shield-alt me-2", style={"color": "#00ff88"}),
                                    "AbuseIPDB Results"
                                ], className="mb-0 text-white")
                            ], className="border-0 bg-transparent"),
                            dbc.CardBody([
                                html.Div([
                                    html.Div([
                                        html.Small("Abuse Confidence", className="text-muted"),
                                        html.H4(f"{abuse_data.get('abuseConfidenceScore', 'N/A')}%", 
                                               className="mb-0", style={"color": "#00ff88"})
                                    ], className="text-center mb-3"),
                                    html.Div([
                                        html.Div([
                                            html.Small("Total Reports", className="text-muted"),
                                            html.H5(abuse_data.get('totalReports', 'N/A'), 
                                                   className="mb-0", style={"color": "#ffffff"})
                                        ], className="text-center"),
                                        html.Div([
                                            html.Small("Last Report", className="text-muted"),
                                            html.H5(abuse_data.get('lastReportedAt', 'N/A')[:10], 
                                                   className="mb-0", style={"color": "#ffffff"})
                                        ], className="text-center")
                                    ], className="row")
                                ])
                            ])
                        ], className="mb-3 border-0", 
                           style={"background": "rgba(0,255,136,0.05)", "borderRadius": "10px"})
                    )
                elif source == 'virustotal' and 'positives' in data:
                    vt_data = data
                    detections = vt_data.get('positives', 0)
                    total = vt_data.get('total', 0)
                    threat_level = "danger" if detections > total//2 else "warning" if detections > 0 else "success"
                    
                    result_cards.append(
                        dbc.Card([
                            dbc.CardHeader([
                                html.H6([
                                    html.I(className="fas fa-virus me-2", style={"color": "#ffd93d"}),
                                    "VirusTotal Results"
                                ], className="mb-0 text-white")
                            ], className="border-0 bg-transparent"),
                            dbc.CardBody([
                                html.Div([
                                    html.Div([
                                        html.Small("Threat Level", className="text-muted"),
                                        html.H4([
                                            f"{detections}/{total}",
                                            html.Br(),
                                            dbc.Badge(
                                                "Malicious" if detections > total//2 else "Suspicious" if detections > 0 else "Clean",
                                                color=threat_level
                                            )
                                        ], className="mb-0", style={"color": "#ffd93d"})
                                    ], className="text-center mb-3"),
                                    html.Div([
                                        html.Small("Scan Date", className="text-muted"),
                                        html.H5(vt_data.get('scan_date', 'N/A')[:10], 
                                               className="mb-0", style={"color": "#ffffff"})
                                    ], className="text-center")
                                ])
                            ])
                        ], className="mb-3 border-0", 
                           style={"background": "rgba(255,217,61,0.05)", "borderRadius": "10px"})
                    )
                elif source == 'alienvault' and isinstance(data, dict):
                    otx_data = data
                    pulse_info = otx_data.get('pulse_info', {}) if isinstance(otx_data.get('pulse_info', {}), dict) else {}
                    pulse_count = pulse_info.get('count')
                    if pulse_count is None:
                        pulse_count = len(otx_data.get('sections', []))
                    result_cards.append(
                        dbc.Card([
                            dbc.CardHeader([
                                html.H6([
                                    html.I(className="fas fa-search me-2", style={"color": "#ff6b6b"}),
                                    "AlienVault OTX Results"
                                ], className="mb-0 text-white")
                            ], className="border-0 bg-transparent"),
                            dbc.CardBody([
                                html.Div([
                                    html.Div([
                                        html.Small("Related Pulses", className="text-muted"),
                                        html.H4(pulse_count if pulse_count is not None else "N/A", 
                                               className="mb-0", style={"color": "#ff6b6b"})
                                    ], className="text-center mb-3"),
                                    html.Div([
                                        html.Small("Threat Intelligence", className="text-muted"),
                                        html.H5("Available in detailed view", 
                                               className="mb-0", style={"color": "#ffffff"})
                                    ], className="text-center")
                                ])
                            ])
                        ], className="mb-3 border-0", 
                           style={"background": "rgba(255,107,107,0.05)", "borderRadius": "10px"})
                    )
        
        if not result_cards:
            return dbc.Alert([
                html.I(className="fas fa-search me-2"),
                "No results found for your query"
            ], color="warning", className="mb-3"), ""
        
        return result_cards, ""
        
    except Exception as e:
        return dbc.Alert([
            html.I(className="fas fa-exclamation-triangle me-2"),
            f"Search error: {str(e)}"
        ], color="danger", className="mb-3"), dash.no_update

# Callback to export IOCs
@app.callback(
    Output("download-ioc", "data"),
    [Input("export-json", "n_clicks"),
     Input("export-csv", "n_clicks"),
     Input("export-stix", "n_clicks")],
    [State("threat-data-store", "data")],
    prevent_initial_call=True
)
def export_iocs(json_clicks, csv_clicks, stix_clicks, data):
    if not data:
        return dash.no_update
    ctx = callback_context
    if not ctx.triggered:
        return dash.no_update
    trigger = ctx.triggered[0]["prop_id"].split(".")[0]
    items = data.get("correlations", [])[:200]

    if trigger == "export-json":
        content = json.dumps(items, indent=2)
        return dcc.send_string(content, "ioc_export.json")

    if trigger == "export-csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["type", "value", "score", "sources", "correlation_count", "last_seen"])
        for item in items:
            writer.writerow([
                item.get("type"),
                item.get("value"),
                item.get("score"),
                ",".join(item.get("sources", [])),
                item.get("correlation_count"),
                item.get("last_seen")
            ])
        return dcc.send_string(buffer.getvalue(), "ioc_export.csv")

    if trigger == "export-stix":
        def stix_pattern(ind):
            ind_type = ind.get("type")
            value = ind.get("value")
            if ind_type == "ip":
                return f"[ipv4-addr:value = '{value}']"
            if ind_type == "domain":
                return f"[domain-name:value = '{value}']"
            if ind_type == "url":
                return f"[url:value = '{value}']"
            if ind_type == "hash":
                if isinstance(value, str):
                    if len(value) == 64:
                        algo = "SHA-256"
                    elif len(value) == 40:
                        algo = "SHA-1"
                    else:
                        algo = "MD5"
                    return f"[file:hashes.'{algo}' = '{value}']"
            return None

        now = datetime.utcnow().isoformat() + "Z"
        objects = []
        for ind in items:
            pattern = stix_pattern(ind)
            if not pattern:
                continue
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"{ind.get('type')}:{ind.get('value')}",
                "pattern": pattern,
                "pattern_type": "stix",
                "confidence": min(100, int(ind.get("score", 0) or 0))
            })
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }
        return dcc.send_string(json.dumps(bundle, indent=2), "ioc_export.stix.json")

    return dash.no_update

# Callback to update source status
@app.callback(
    Output('source-status', 'children'),
    [Input('threat-data-store', 'data')]
)
def update_source_status(data):
    if not data:
        return ""
    
    sources = data.get('sources', {})
    connections = data.get('connections', {})
    status_cards = []
    
    source_info = {
        'abuseipdb': {
            'name': 'AbuseIPDB', 
            'icon': 'fas fa-shield-alt',
            'color': '#00ff88',
            'description': 'IP reputation and abuse reports'
        },
        'alienvault': {
            'name': 'AlienVault OTX', 
            'icon': 'fas fa-search',
            'color': '#ff6b6b',
            'description': 'Threat pulses and indicators'
        },
        'virustotal': {
            'name': 'VirusTotal', 
            'icon': 'fas fa-virus',
            'color': '#ffd93d',
            'description': 'File and URL scanning'
        }
    }
    
    for source_key, source_info_item in source_info.items():
        conn = connections.get(source_key)
        if conn is not None:
            if conn.get('online') is True:
                status_badge = dbc.Badge("Online", color="success")
                if conn.get('warning') == 'rate_limited':
                    status_text = "Connected (rate limited)"
                    status_icon = "fas fa-exclamation-triangle"
                else:
                    status_text = "Connected and active"
                    status_icon = "fas fa-check-circle"
            else:
                status_badge = dbc.Badge("Offline", color="danger", className="pulse")
                status_text = "Connection failed"
                status_icon = "fas fa-times-circle"
        elif source_key in sources:
            if 'error' in sources[source_key]:
                status_badge = dbc.Badge("Offline", color="danger", className="pulse")
                status_text = "Connection failed"
                status_icon = "fas fa-times-circle"
            else:
                status_badge = dbc.Badge("Online", color="success")
                status_text = "Connected and active"
                status_icon = "fas fa-check-circle"
        else:
            status_badge = dbc.Badge("Not Configured", color="secondary")
            status_text = "API key required"
            status_icon = "fas fa-exclamation-circle"
        
        status_cards.append(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.Div([
                            html.I(className=f"{source_info_item['icon']} me-3", 
                                  style={"color": source_info_item['color'], "fontSize": "1.5rem"}),
                            html.Div([
                                html.H6(source_info_item['name'], className="mb-1", 
                                       style={"color": "#ffffff", "fontWeight": "500"}),
                                html.Small(source_info_item['description'], className="text-muted")
                            ])
                        ], className="d-flex align-items-center mb-3"),
                        html.Div([
                            html.Div([
                                html.I(className=f"{status_icon} me-2", style={"fontSize": "1rem"}),
                                status_badge
                            ], className="d-flex align-items-center"),
                            html.Small(status_text, className="text-muted ms-3")
                        ], className="d-flex align-items-center justify-content-between")
                    ])
                ])
            ], className="mb-3 border-0", 
               style={"background": "rgba(255,255,255,0.02)", "borderRadius": "10px"})
        )
    
    return status_cards

# Callback to update top risk indicators
@app.callback(
    Output('top-risk-indicators', 'children'),
    [Input('threat-data-store', 'data')]
)
def update_top_risk_indicators(data):
    if not data or not data.get('scored_indicators'):
        return dbc.Alert([
            html.I(className="fas fa-info-circle me-2"),
            "No risk indicators available"
        ], color="info", className="mb-3")
    
    top_indicators = data['scored_indicators'][:5]
    indicator_cards = []
    
    for indicator in top_indicators:
        color_map = {
            "Critical": "#ff6b6b",
            "High": "#ffd93d",
            "Medium": "#00ff88",
            "Low": "#6bcf7f"
        }
        
        indicator_cards.append(
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Div([
                            html.I(className="fas fa-shield-alt me-2", style={"color": color_map.get(indicator['level'], "#6c757d")}),
                            html.Strong(f"{indicator['color']} {indicator['level']} Risk"),
                            html.Br(),
                            html.Span(f"{indicator['type'].upper()}: {indicator['value']}", style={"fontSize": "0.9rem"}),
                            html.Br(),
                            html.Small(f"Score: {indicator['score']}/100 | Reports: {indicator.get('abuse_reports', 'N/A')} | Last Seen: {indicator.get('last_seen', 'N/A')[:10] if indicator.get('last_seen') else 'N/A'}", className="text-muted")
                        ])
                    ], className="p-3", style={"background": f"rgba({color_map.get(indicator['level'], '#6c757d')}, 0.1)", "borderRadius": "10px", "marginBottom": "10px"})
                ])
            ])
        )
    
    return indicator_cards

# Callback to update threat map
@app.callback(
    Output('threat-map', 'figure'),
    [Input('threat-data-store', 'data')]
)
def update_threat_map(data):
    if not data or not data.get('scored_indicators'):
        return go.Figure()
    
    from collections import defaultdict
    country_counts = defaultdict(int)
    country_avg_score = defaultdict(list)
    
    for ind in data['scored_indicators']:
        country = ind.get('country')
        if country:
            country_counts[country] += 1
            country_avg_score[country].append(ind['score'])
    
    if not country_counts:
        return go.Figure()
    
    countries = []
    counts = []
    avg_scores = []
    
    for country, count in country_counts.items():
        countries.append(country)
        counts.append(count)
        avg_scores.append(sum(country_avg_score[country]) / len(country_avg_score[country]))
    
    # Use scatter_geo with size and color
    fig = go.Figure(data=go.Scattergeo(
        locations=countries,
        locationmode='ISO-3',  # country codes
        mode='markers',
        marker=dict(
            size=[c*3 + 10 for c in counts],  # scale size, min 10
            color=avg_scores,
            colorscale='RdYlGn_r',  # red for high, green for low
            showscale=True,
            colorbar=dict(title="Avg Risk Score", titleside="right")
        ),
        text=[f"{c}: {ct} threats, avg score {avg:.1f}" for c, ct, avg in zip(countries, counts, avg_scores)],
        hoverinfo='text'
    ))
    
    fig.update_layout(
        title='Global Threat Distribution',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff'),
        geo=dict(
            showframe=False,
            showcoastlines=True,
            projection_type='natural earth',
            bgcolor='rgba(0,0,0,0)',
            showcountries=True,
            countrycolor='rgba(255,255,255,0.1)'
        ),
        margin=dict(t=50, b=50, l=50, r=50)
    )
    
    return fig

# Callback for exporting data
@app.callback(
    Output("download", "data"),
    [Input("export-json-btn", "n_clicks"), Input("export-csv-btn", "n_clicks")],
    [State("threat-data-store", "data")],
    prevent_initial_call=True
)
def export_data(json_clicks, csv_clicks, data):
    ctx = callback_context
    if not ctx.triggered:
        return dash.no_update
    
    button_id = ctx.triggered[0]["prop_id"].split(".")[0]
    
    if not data or not data.get("scored_indicators"):
        return dash.no_update
    
    if button_id == "export-json-btn":
        return dict(content=json.dumps(data["scored_indicators"], indent=2), filename="threat_indicators.json")
    elif button_id == "export-csv-btn":
        output = io.StringIO()
        if data["scored_indicators"]:
            writer = csv.DictWriter(output, fieldnames=data["scored_indicators"][0].keys())
            writer.writeheader()
            writer.writerows(data["scored_indicators"])
        return dict(content=output.getvalue(), filename="threat_indicators.csv")

if __name__ == "__main__":
    app.run_server(debug=True, host="0.0.0.0", port=8050)
