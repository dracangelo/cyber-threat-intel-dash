import os
import time
import ipaddress
import re
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dotenv import load_dotenv
from threat_integrations.abuseipdb import AbuseIPDBClient
from threat_integrations.alienvault import AlienVaultClient
from threat_integrations.virustotal import VirusTotalClient

class ThreatDataAggregator:
    def __init__(self):
        load_dotenv()
        
        # Initialize API clients
        self.abuse_client = None
        self.otx_client = None
        self.vt_client = None
        
        # Initialize clients if API keys are available
        if os.getenv("ABUSEIPDB_API_KEY"):
            self.abuse_client = AbuseIPDBClient(os.getenv("ABUSEIPDB_API_KEY"))
        
        if os.getenv("ALIENVAULT_API_KEY"):
            self.otx_client = AlienVaultClient(os.getenv("ALIENVAULT_API_KEY"))
        
        if os.getenv("VIRUSTOTAL_API_KEY"):
            self.vt_client = VirusTotalClient(os.getenv("VIRUSTOTAL_API_KEY"))
        
        self.last_update = None
        self.cached_data = {}
        self.cache_duration = timedelta(minutes=5)  # Cache for 5 minutes
    
    def is_cache_valid(self) -> bool:
        """Check if cached data is still valid"""
        if not self.last_update:
            return False
        
        return datetime.now() - self.last_update < self.cache_duration
    
    def get_aggregated_threat_data(self, force_refresh: bool = False) -> Dict:
        """Get aggregated threat data from all sources"""
        if not force_refresh and self.is_cache_valid():
            return self.cached_data
        
        aggregated_data = {
            "timestamp": datetime.now().isoformat(),
            "sources": {},
            "connections": {},
            "summary": {
                "total_threats": 0,
                "high_risk_indicators": 0,
                "active_campaigns": 0,
                "trending_threats": []
            },
            "indicators": {
                "malicious_ips": [],
                "suspicious_domains": [],
                "malware_hashes": []
            },
            "statistics": {
                "by_source": {},
                "by_type": {},
                "timeline": {}
            },
            "alerts": []
        }
        
        # Collect data from each source
        if self.abuse_client:
            try:
                aggregated_data["connections"]["abuseipdb"] = self.abuse_client.test_connection()
                if aggregated_data["connections"]["abuseipdb"].get("online") is True and aggregated_data["connections"]["abuseipdb"].get("warning") != "rate_limited":
                    abuse_data = self.abuse_client.get_threat_stats()
                    aggregated_data["sources"]["abuseipdb"] = abuse_data
                else:
                    aggregated_data["sources"]["abuseipdb"] = {"error": "Data temporarily unavailable", "source": "AbuseIPDB"}
                
                # Process AbuseIPDB data
                if "abuse_data" in locals() and "error" not in abuse_data:
                    aggregated_data["summary"]["total_threats"] += abuse_data.get("total_reports", 0)
                    aggregated_data["summary"]["high_risk_indicators"] += abuse_data.get("last_24h_reports", 0)
                    
                    # Add to statistics
                    aggregated_data["statistics"]["by_source"]["abuseipdb"] = {
                        "reports": abuse_data.get("total_reports", 0),
                        "last_24h": abuse_data.get("last_24h_reports", 0),
                        "last_7d": abuse_data.get("last_7d_reports", 0)
                    }
                    
                    # Add trending threats from categories
                    top_categories = abuse_data.get("top_categories", {})
                    for category, count in list(top_categories.items())[:5]:
                        aggregated_data["summary"]["trending_threats"].append({
                            "type": "category",
                            "name": str(category),
                            "count": count,
                            "source": "abuseipdb"
                        })
                    
                    # Generate alerts for high activity
                    if abuse_data.get("last_24h_reports", 0) > 100:
                        aggregated_data["alerts"].append({
                            "level": "high",
                            "message": f"High abuse activity detected: {abuse_data.get('last_24h_reports')} reports in 24h",
                            "source": "abuseipdb",
                            "timestamp": datetime.now().isoformat()
                        })
                        
            except Exception as e:
                aggregated_data["sources"]["abuseipdb"] = {"error": str(e)}
                aggregated_data["connections"]["abuseipdb"] = {"online": False, "error": str(e)}
        
        if self.otx_client:
            try:
                aggregated_data["connections"]["alienvault"] = self.otx_client.test_connection()
                if aggregated_data["connections"]["alienvault"].get("online") is True and aggregated_data["connections"]["alienvault"].get("warning") != "rate_limited":
                    otx_data = self.otx_client.get_threat_stats()
                    aggregated_data["sources"]["alienvault"] = otx_data
                else:
                    aggregated_data["sources"]["alienvault"] = {"error": "Data temporarily unavailable", "source": "AlienVault OTX"}
                
                # Process OTX data
                if "otx_data" in locals() and "error" not in otx_data:
                    aggregated_data["summary"]["total_threats"] += otx_data.get("total_pulses", 0)
                    aggregated_data["summary"]["active_campaigns"] += otx_data.get("total_pulses", 0)
                    
                    # Add to statistics
                    aggregated_data["statistics"]["by_source"]["alienvault"] = {
                        "pulses": otx_data.get("total_pulses", 0),
                        "indicators": otx_data.get("total_indicators", 0),
                        "last_24h": otx_data.get("last_24h_pulses", 0),
                        "last_7d": otx_data.get("last_7d_pulses", 0)
                    }
                    
                    # Add trending threats from tags
                    top_tags = otx_data.get("top_tags", {})
                    for tag, count in list(top_tags.items())[:5]:
                        aggregated_data["summary"]["trending_threats"].append({
                            "type": "tag",
                            "name": str(tag),
                            "count": count,
                            "source": "alienvault"
                        })
                    
                    # Generate alerts for new campaigns
                    if otx_data.get("last_24h_pulses", 0) > 10:
                        aggregated_data["alerts"].append({
                            "level": "medium",
                            "message": f"New threat campaigns detected: {otx_data.get('last_24h_pulses')} pulses in 24h",
                            "source": "alienvault",
                            "timestamp": datetime.now().isoformat()
                        })
                        
            except Exception as e:
                aggregated_data["sources"]["alienvault"] = {"error": str(e)}
                aggregated_data["connections"]["alienvault"] = {"online": False, "error": str(e)}
        
        if self.vt_client:
            try:
                aggregated_data["connections"]["virustotal"] = {"online": True}
                vt_data = self.vt_client.get_threat_stats()
                aggregated_data["sources"]["virustotal"] = vt_data
                
                # Process VirusTotal data
                if "error" not in vt_data:
                    scan_dist = vt_data.get("scan_distribution", {})
                    malicious_count = scan_dist.get("malicious", 0)
                    suspicious_count = scan_dist.get("suspicious", 0)
                    
                    aggregated_data["summary"]["high_risk_indicators"] += malicious_count + suspicious_count
                    
                    # Add to statistics
                    aggregated_data["statistics"]["by_source"]["virustotal"] = scan_dist
                    
                    # Generate alerts for malware detections
                    if malicious_count > 0:
                        aggregated_data["alerts"].append({
                            "level": "critical",
                            "message": f"Malware detected: {malicious_count} malicious files/URLs",
                            "source": "virustotal",
                            "timestamp": datetime.now().isoformat()
                        })
                        
            except Exception as e:
                aggregated_data["sources"]["virustotal"] = {"error": str(e)}
                aggregated_data["connections"]["virustotal"] = {"online": False, "error": str(e)}
        
        # Sort alerts by severity
        alert_levels = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        aggregated_data["alerts"].sort(
            key=lambda x: alert_levels.get(x["level"], 0), 
            reverse=True
        )
        
        # Limit alerts to top 10
        aggregated_data["alerts"] = aggregated_data["alerts"][:10]
        
        # Sort trending threats by count
        aggregated_data["summary"]["trending_threats"].sort(
            key=lambda x: x["count"], 
            reverse=True
        )
        
        # Limit to top 10 trending threats
        aggregated_data["summary"]["trending_threats"] = aggregated_data["summary"]["trending_threats"][:10]
        
        # Update cache
        self.cached_data = aggregated_data
        self.last_update = datetime.now()
        
        return aggregated_data
    
    def get_threat_timeline(self, days: int = 7) -> Dict:
        """Get threat timeline data for the last N days"""
        timeline = {}
        end_date = datetime.now()
        
        for i in range(days):
            date = end_date - timedelta(days=i)
            date_str = date.strftime("%Y-%m-%d")
            timeline[date_str] = {
                "abuse_reports": 0,
                "otx_pulses": 0,
                "vt_detections": 0
            }
        
        # In a real implementation, you would query historical data
        # For now, we'll return the template with mock data
        return timeline
    
    def search_indicators(self, query: str, indicator_type: str = "all") -> Dict:
        """Search for specific indicators across all sources"""
        results = {
            "query": query,
            "type": indicator_type,
            "results": {},
            "timestamp": datetime.now().isoformat()
        }
        normalized_query = (query or "").strip()
        inferred_type = self._infer_indicator_type(normalized_query)
        effective_type = inferred_type if indicator_type == "all" else indicator_type
        
        # Search in AbuseIPDB (if query looks like an IP)
        if self.abuse_client and effective_type == "ip":
            try:
                ip_result = self.abuse_client.check_ip(normalized_query)
                results["results"]["abuseipdb"] = ip_result
            except Exception as e:
                results["results"]["abuseipdb"] = {"error": str(e)}
        
        # Search in OTX
        if self.otx_client:
            try:
                otx_type_map = {
                    "ip": "IPv4",
                    "domain": "domain",
                    "url": "url",
                    "hash": "file"
                }
                otx_type = otx_type_map.get(effective_type)
                if otx_type:
                    otx_result = self.otx_client.search_indicators(normalized_query, otx_type)
                    results["results"]["alienvault"] = otx_result
                else:
                    results["results"]["alienvault"] = {"error": "Unsupported indicator type"}
            except Exception as e:
                results["results"]["alienvault"] = {"error": str(e)}
        
        # Search in VirusTotal
        if self.vt_client:
            try:
                if indicator_type in ["all", "url"]:
                    vt_result = self.vt_client.get_url_report(query)
                    results["results"]["virustotal"] = vt_result
                elif indicator_type in ["all", "ip"]:
                    vt_result = self.vt_client.get_ip_report(query)
                    results["results"]["virustotal"] = vt_result
                elif indicator_type in ["all", "domain"]:
                    vt_result = self.vt_client.get_domain_report(query)
                    results["results"]["virustotal"] = vt_result
            except Exception as e:
                results["results"]["virustotal"] = {"error": str(e)}
        
        return results

    @staticmethod
    def _infer_indicator_type(query: str) -> Optional[str]:
        if not query:
            return None
        try:
            ipaddress.ip_address(query)
            return "ip"
        except ValueError:
            pass
        if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", query):
            return "hash"
        parsed = urlparse(query)
        if parsed.scheme and parsed.netloc:
            return "url"
        if "." in query and " " not in query and "/" not in query:
            return "domain"
        return None
