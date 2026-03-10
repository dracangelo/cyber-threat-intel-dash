import requests
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

class AlienVaultClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "X-OTX-API-KEY": api_key
        }

    def test_connection(self) -> Dict:
        url = f"{self.base_url}/indicators/IPv4/8.8.8.8/general"
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 429:
                return {"online": True, "warning": "rate_limited"}
            response.raise_for_status()
            return {"online": True}
        except requests.exceptions.RequestException as e:
            return {"online": False, "error": str(e)}
    
    def get_pulses(self, modified_since: Optional[str] = None, limit: int = 20) -> Dict:
        """Get recent threat pulses"""
        url = f"{self.base_url}/pulses"
        params = {"limit": limit}
        
        if modified_since:
            params["modified_since"] = modified_since
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_pulse_details(self, pulse_id: str) -> Dict:
        """Get detailed information about a specific pulse"""
        url = f"{self.base_url}/pulses/{pulse_id}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_indicators(self, pulse_id: str) -> Dict:
        """Get indicators for a specific pulse"""
        url = f"{self.base_url}/pulses/{pulse_id}/indicators"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_subscriptions(self) -> Dict:
        """Get user's subscribed pulses"""
        url = f"{self.base_url}/pulses/subscribed"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def search_indicators(self, indicator: str, indicator_type: str) -> Dict:
        """Search for indicators in OTX database"""
        url = f"{self.base_url}/indicators/{indicator_type}/{indicator}/general"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_threat_stats(self) -> Dict:
        """Get threat statistics for dashboard"""
        try:
            # Get recent pulses for stats
            pulses_response = self.get_pulses(limit=100)
            
            if "results" in pulses_response:
                pulses = pulses_response["results"]
                
                # Analyze pulses for statistics
                tags = {}
                authors = {}
                indicators_by_type = {}
                last_24h = 0
                last_7d = 0
                
                now = datetime.now(timezone.utc)
                
                for pulse in pulses:
                    # Count tags
                    for tag in pulse.get("tags", []):
                        tags[tag] = tags.get(tag, 0) + 1
                    
                    # Count authors
                    author = pulse.get("author_name", "Unknown")
                    authors[author] = authors.get(author, 0) + 1
                    
                    # Count indicators by type
                    for indicator in pulse.get("indicators", []):
                        ind_type = indicator.get("type", "unknown")
                        indicators_by_type[ind_type] = indicators_by_type.get(ind_type, 0) + 1
                    
                    # Time-based counts
                    created_time = datetime.fromisoformat(pulse["created"].replace("Z", "+00:00"))
                    if created_time.tzinfo is None:
                        created_time = created_time.replace(tzinfo=timezone.utc)
                    time_diff = now - created_time
                    
                    if time_diff.total_seconds() <= 86400:  # Last 24 hours
                        last_24h += 1
                    if time_diff.total_seconds() <= 604800:  # Last 7 days
                        last_7d += 1
                
                return {
                    "total_pulses": len(pulses),
                    "last_24h_pulses": last_24h,
                    "last_7d_pulses": last_7d,
                    "total_indicators": sum(indicators_by_type.values()),
                    "top_tags": dict(sorted(tags.items(), key=lambda x: x[1], reverse=True)[:10]),
                    "top_authors": dict(sorted(authors.items(), key=lambda x: x[1], reverse=True)[:10]),
                    "indicator_types": indicators_by_type,
                    "source": "AlienVault OTX"
                }
            else:
                return {"error": "No data available", "source": "AlienVault OTX"}
                
        except Exception as e:
            return {"error": str(e), "source": "AlienVault OTX"}
