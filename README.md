# 🛡️ Cyber Threat Intelligence Dashboard

A real-time cyber threat intelligence dashboard that aggregates data from multiple threat intelligence feeds including AbuseIPDB, AlienVault OTX, and VirusTotal. This dashboard provides actionable intelligence through visualizations and real-time monitoring.

## 🚀 Features

- **Multi-Source Integration**: Aggregates threat data from AbuseIPDB, AlienVault OTX, and VirusTotal
- **Real-Time Updates**: Automatically refreshes data every 30 seconds
- **Interactive Visualizations**: Charts and graphs for threat analysis
- **Alert System**: Real-time alerts for high-priority threats
- **Indicator Search**: Search IPs, domains, URLs, and hashes across all sources
- **Threat Timeline**: 7-day threat activity timeline
- **Source Status Monitoring**: Real-time status of all data sources
- **Responsive Design**: Works on desktop and mobile devices

## 📋 Prerequisites

- Python 3.8 or higher
- API keys for threat intelligence feeds (see setup section)
- Git (for cloning)

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cyber-threat-dashboard
```

### 2. Create Virtual Environment

```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit the `.env` file with your API keys:

```env
# API Keys for Threat Intelligence Feeds
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ALIENVAULT_API_KEY=your_alienvault_api_key_here

# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your_secret_key_here

# Dashboard Configuration
REFRESH_INTERVAL=30000  # Refresh interval in milliseconds (30 seconds)
```

## 🔑 Getting API Keys

### AbuseIPDB
1. Visit [AbuseIPDB](https://abuseipdb.com/)
2. Create a free account
3. Go to your account settings and generate an API key
4. Copy the key to your `.env` file

### AlienVault OTX
1. Visit [AlienVault OTX](https://otx.alienvault.com/)
2. Create a free account
3. Go to your profile settings and find your API key
4. Copy the key to your `.env` file

### VirusTotal
1. Visit [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Go to your profile and request an API key
4. Copy the key to your `.env` file

## 🚀 Running the Dashboard

### Method 1: Development Mode

```bash
python app.py
```

The dashboard will be available at `http://localhost:8050`

### Method 2: Production Mode with Gunicorn

```bash
gunicorn -w 4 -b 0.0.0.0:8050 app:server
```

## 📊 Dashboard Components

### Key Metrics Cards
- **Total Threats**: Combined threat count from all sources
- **High Risk Indicators**: Number of high-priority threats
- **Active Campaigns**: Currently active threat campaigns
- **Data Sources**: Number of connected threat intelligence sources

### Visualizations
- **Threat Distribution by Source**: Pie chart showing threat distribution
- **Trending Threats**: Bar chart of top trending threats
- **Threat Timeline**: 7-day timeline of threat activity
- **Threat Categories**: Breakdown of threat types

### Alert System
Real-time alerts for:
- High abuse activity (AbuseIPDB)
- New threat campaigns (AlienVault OTX)
- Malware detections (VirusTotal)

### Search Functionality
Search across all sources for:
- IP addresses
- Domain names
- URLs
- File hashes

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | Required |
| `ALIENVAULT_API_KEY` | AlienVault OTX API key | Required |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | Required |
| `FLASK_ENV` | Flask environment | `development` |
| `SECRET_KEY` | Flask secret key | Auto-generated |
| `REFRESH_INTERVAL` | Dashboard refresh interval (ms) | `30000` |

### Rate Limits

- **AbuseIPDB**: 1,000 requests/day (free tier)
- **AlienVault OTX**: 30 requests/minute (free tier)
- **VirusTotal**: 4 requests/minute (free tier)

## 🐛 Troubleshooting

### Common Issues

1. **API Key Errors**
   - Verify your API keys are correct in the `.env` file
   - Check if your API keys have expired
   - Ensure you haven't exceeded rate limits

2. **Connection Issues**
   - Check your internet connection
   - Verify firewall settings allow outbound connections
   - Check if API endpoints are accessible

3. **Dashboard Not Loading**
   - Ensure all dependencies are installed
   - Check if port 8050 is available
   - Verify Python version compatibility

4. **Missing Data**
   - Check the "Data Source Status" section
   - Verify API keys are configured correctly
   - Check for error messages in the console

### Debug Mode

Enable debug mode by setting:
```env
FLASK_ENV=development
```

This will provide detailed error messages and auto-reload on code changes.

## 📁 Project Structure

```
cyber-threat-dashboard/
├── app.py                      # Main dashboard application
├── config.py                   # Configuration settings
├── data_aggregator.py          # Data aggregation logic
├── requirements.txt            # Python dependencies
├── .env.example               # Environment variables template
├── .gitignore                 # Git ignore file
├── README.md                  # This file
└── threat_integrations/       # API integration modules
    ├── __init__.py
    ├── abuseipdb.py           # AbuseIPDB integration
    ├── alienvault.py          # AlienVault OTX integration
    └── virustotal.py          # VirusTotal integration
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔒 Security Considerations

- Never commit your `.env` file to version control
- Use strong, unique API keys
- Monitor API usage to avoid rate limiting
- Consider using a reverse proxy in production
- Enable HTTPS in production environments

## 📈 Performance Optimization

- Data is cached for 5 minutes to reduce API calls
- Dashboard refreshes every 30 seconds by default
- Consider using Redis for distributed caching in production
- Monitor API rate limits and implement backoff strategies

## 🆘 Support

If you encounter issues:
1. Check the troubleshooting section
2. Review the console output for error messages
3. Verify your API keys and rate limits
4. Create an issue with detailed information

## 🎯 Use Cases

This dashboard is perfect for:
- **SOC Teams**: Real-time threat monitoring
- **Security Analysts**: Threat intelligence research
- **CISOs**: Executive threat reporting
- **Penetration Testers**: Indicator research
- **Security Researchers**: Threat trend analysis

## 🔄 Future Enhancements

- Additional threat intelligence sources
- Machine learning-based threat scoring
- Custom alert rules and notifications
- Historical data analysis
- Export functionality for reports
- Integration with SIEM systems
- Mobile app companion

---

**⚠️ Disclaimer**: This dashboard is for educational and research purposes. Always verify threat intelligence from multiple sources before taking action.
