import dash
from dash import dcc, html, Input, Output, State, callback_context
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
from data_aggregator import ThreatDataAggregator

# Initialize the Dash app with a modern theme
app = dash.Dash(__name__, 
    external_stylesheets=[
        dbc.themes.CYBORG,
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css'
    ],
    suppress_callback_exceptions=True
)
app.title = "Cyber Threat Intelligence Dashboard"

# Initialize data aggregator
aggregator = ThreatDataAggregator()

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
    dcc.Store(id='threat-data-store')
    
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

if __name__ == '__main__':
    app.run_server(debug=True, host='0.0.0.0', port=8050)
