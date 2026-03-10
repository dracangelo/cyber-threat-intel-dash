import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Configuration class for the Cyber Threat Dashboard"""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    
    # API Keys
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
    ALIENVAULT_API_KEY = os.getenv('ALIENVAULT_API_KEY')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    
    # Dashboard Configuration
    REFRESH_INTERVAL = int(os.getenv('REFRESH_INTERVAL', 30000))  # milliseconds
    CACHE_DURATION = 300  # seconds (5 minutes)
    
    # API Rate Limits
    ABUSEIPDB_RATE_LIMIT = 1000  # requests per day
    ALIENVAULT_RATE_LIMIT = 30   # requests per minute
    VIRUSTOTAL_RATE_LIMIT = 4    # requests per minute (free tier)
    
    # Data Retention
    MAX_ALERTS = 50
    MAX_TRENDING_THREATS = 20
    TIMELINE_DAYS = 7
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = 'threat_dashboard.log'
    
    @classmethod
    def validate_config(cls):
        """Validate that required configuration is present"""
        missing_keys = []
        
        if not cls.ABUSEIPDB_API_KEY:
            missing_keys.append('ABUSEIPDB_API_KEY')
        if not cls.ALIENVAULT_API_KEY:
            missing_keys.append('ALIENVAULT_API_KEY')
        if not cls.VIRUSTOTAL_API_KEY:
            missing_keys.append('VIRUSTOTAL_API_KEY')
        
        return missing_keys
