import requests
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

class AbuseIPDBClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }

    def test_connection(self) -> Dict:
        url = f"{self.base_url}/check"
        params = {
            "ipAddress": "8.8.8.8",
            "maxAgeInDays": 90
        }

        try:
            start_time = time.time()
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            response_time = time.time() - start_time
            if response.status_code == 429:
                return {"online": True, "warning": "rate_limited", "response_time": response_time}
            response.raise_for_status()
            return {"online": True, "response_time": response_time}
        except requests.exceptions.RequestException as e:
            return {"online": False, "error": str(e), "response_time": None}
    
    def check_ip(self, ip_address: str, max_age_in_days: int = 90) -> Dict:
        """Check if an IP address is malicious"""
        url = f"{self.base_url}/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_in_days,
            "verbose": ""
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_recent_reports(self, limit: int = 10000, minimum_confidence: int = 75) -> Dict:
        """Get recent abusive IPs from blacklist"""
        url = f"{self.base_url}/blacklist"
        params = {
            "limit": limit,
            "confidenceMinimum": minimum_confidence
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            data_list = data.get("data", []) if isinstance(data, dict) else []
            reports = []
            for ip_entry in data_list:
                if ip_entry is None:
                    continue
                # Create a mock report entry
                report = {
                    "ipAddress": ip_entry.get("ipAddress"),
                    "categories": ip_entry.get("categories", []),
                    "abuseConfidenceScore": ip_entry.get("abuseConfidenceScore", 0),
                    "totalReports": ip_entry.get("totalReports", 0),
                    "lastReportedAt": ip_entry.get("lastReportedAt"),
                    "createdAt": ip_entry.get("lastReportedAt"),  # Use lastReportedAt as createdAt
                    "reporterCountryCode": ip_entry.get("countryCode")
                }
                reports.append(report)
            return {"data": reports}
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_blacklist(self, limit: int = 10000, minimum_confidence: int = 75) -> Dict:
        """Get current blacklist of malicious IPs"""
        url = f"{self.base_url}/blacklist"
        params = {
            "limit": limit,
            "confidenceMinimum": minimum_confidence
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_threat_stats(self) -> Dict:
        """Get threat statistics for dashboard"""
        try:
            # Get recent reports for stats
            recent_reports = self.get_recent_reports(limit=1000)
            if "error" in recent_reports:
                return {"error": recent_reports.get("error"), "source": "AbuseIPDB"}

            reports = recent_reports.get("data")
            if not isinstance(reports, list):
                return {"error": "No data available", "source": "AbuseIPDB"}

            # Analyze reports for statistics
            categories = {}
            countries = {}
            last_24h = 0
            last_7d = 0
            
            now = datetime.now(timezone.utc)
            
            for report in reports:
                # Count categories
                for category in report.get("categories", []):
                    categories[category] = categories.get(category, 0) + 1
                
                # Count countries
                country = report.get("reporterCountryCode", "Unknown")
                countries[country] = countries.get(country, 0) + 1
                
                # Time-based counts
                report_time = datetime.fromisoformat(report["createdAt"].replace("Z", "+00:00"))
                time_diff = now - report_time
                
                if time_diff.total_seconds() <= 86400:  # Last 24 hours
                    last_24h += 1
                if time_diff.total_seconds() <= 604800:  # Last 7 days
                    last_7d += 1
            
            return {
                "total_reports": len(reports),
                "last_24h_reports": last_24h,
                "last_7d_reports": last_7d,
                "top_categories": dict(sorted(categories.items(), key=lambda x: x[1], reverse=True)[:10]),
                "top_countries": dict(sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]),
                "source": "AbuseIPDB"
            }
                
        except Exception as e:
            return {"error": str(e), "source": "AbuseIPDB"}
