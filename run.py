#!/usr/bin/env python3
"""
Cyber Threat Intelligence Dashboard - Run Script
This script provides an easy way to start the dashboard with proper error handling
"""

import os
import sys
from dotenv import load_dotenv
from config import Config

def check_dependencies():
    """Check if all required dependencies are installed"""
    try:
        import dash
        import requests
        import plotly
        import pandas
        print("✅ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def check_api_keys():
    """Check if API keys are configured"""
    load_dotenv()
    
    api_keys = {
        'AbuseIPDB': os.getenv('ABUSEIPDB_API_KEY'),
        'AlienVault OTX': os.getenv('ALIENVAULT_API_KEY'),
        'VirusTotal': os.getenv('VIRUSTOTAL_API_KEY')
    }
    
    print("\n🔑 API Key Configuration:")
    configured = 0
    
    for service, key in api_keys.items():
        if key and key != f'your_{service.lower().replace(" ", "_")}_api_key_here':
            print(f"✅ {service}: Configured")
            configured += 1
        else:
            print(f"❌ {service}: Not configured")
    
    if configured == 0:
        print("\n⚠️  No API keys configured. Please edit your .env file.")
        print("   The dashboard will run but show limited data.")
    elif configured < 3:
        print(f"\n⚠️  {configured}/3 API keys configured. Some features may be limited.")
    else:
        print("\n✅ All API keys configured!")
    
    return configured > 0

def main():
    """Main function to run the dashboard"""
    print("🛡️  Cyber Threat Intelligence Dashboard")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check API keys
    check_api_keys()
    
    # Check if .env file exists
    if not os.path.exists('.env'):
        print("\n⚠️  .env file not found. Creating from template...")
        if os.path.exists('.env.example'):
            import shutil
            shutil.copy('.env.example', '.env')
            print("✅ .env file created. Please edit it with your API keys.")
        else:
            print("❌ .env.example file not found!")
            sys.exit(1)
    
    print("\n🚀 Starting dashboard...")
    print("   Dashboard will be available at: http://localhost:8050")
    print("   Press Ctrl+C to stop the dashboard")
    print("\n" + "=" * 50)
    
    try:
        # Import and run the app
        from app import app
        app.run_server(debug=True, host='0.0.0.0', port=8050)
    except KeyboardInterrupt:
        print("\n\n👋 Dashboard stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting dashboard: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
