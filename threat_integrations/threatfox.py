import requests
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class ThreatFoxClient:
    def __init__(self, api_key: str = None):
        # ThreatFox API doesn't require API key
        self.api_key = api_key
        self.base_url = "https://threatfox.abuse.ch/api/v1/"
    
    def get_recent_iocs(self, days: int = 7) -> Dict:
        """Get recent IOCs from ThreatFox"""
        payload = {
            "query": "get_recent",
            "days": days
        }
        
        try:
            response = requests.post(self.base_url, json=payload, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_ioc_details(self, ioc: str) -> Dict:
        """Get details for a specific IOC"""
        payload = {
            "query": "get_ioc",
            "ioc": ioc
        }
        
        try:
            response = requests.post(self.base_url, json=payload, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def search_iocs(self, query: str, type: str = "all") -> Dict:
        """Search for IOCs"""
        payload = {
            "query": "search_ioc",
            "search_term": query
        }
        
        try:
            response = requests.post(self.base_url, json=payload, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_threat_stats(self) -> Dict:
        """Get threat statistics for dashboard"""
        try:
            # Get recent IOCs for stats
            iocs_response = self.get_recent_iocs(days=7)
            
            if iocs_response.get("query_status") == "ok" and "data" in iocs_response:
                iocs = iocs_response["data"]
                
                # Analyze IOCs for statistics
                malware_types = {}
                ioc_types = {}
                last_24h = 0
                last_7d = 0
                
                now = datetime.utcnow()
                
                for ioc in iocs:
                    # Count malware types
                    malware = ioc.get("malware", "unknown")
                    malware_types[malware] = malware_types.get(malware, 0) + 1
                    
                    # Count IOC types
                    ioc_type = ioc.get("ioc_type", "unknown")
                    ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
                    
                    # Time-based counts (first_seen is in YYYY-MM-DD format)
                    try:
                        first_seen = datetime.strptime(ioc.get("first_seen", ""), "%Y-%m-%d")
                        time_diff = now - first_seen
                        
                        if time_diff.total_seconds() <= 86400:  # Last 24 hours
                            last_24h += 1
                        if time_diff.total_seconds() <= 604800:  # Last 7 days
                            last_7d += 1
                    except:
                        pass  # Skip if date parsing fails
                
                return {
                    "total_iocs": len(iocs),
                    "last_24h_iocs": last_24h,
                    "last_7d_iocs": last_7d,
                    "top_malware": dict(sorted(malware_types.items(), key=lambda x: x[1], reverse=True)[:10]),
                    "ioc_types": ioc_types,
                    "source": "ThreatFox"
                }
            else:
                return {"error": "No data available", "source": "ThreatFox"}
                
        except Exception as e:
            return {"error": str(e), "source": "ThreatFox"}
