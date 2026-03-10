import os
import ipaddress
import re
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dotenv import load_dotenv
from threat_integrations.abuseipdb import AbuseIPDBClient
from threat_integrations.alienvault import AlienVaultClient
from threat_integrations.virustotal import VirusTotalClient
from storage import ThreatStorage

class ThreatDataAggregator:
    def __init__(self):
        load_dotenv()

        # Initialize API clients
        self.abuse_client = None
        self.otx_client = None
        self.vt_client = None

        if os.getenv("ABUSEIPDB_API_KEY"):
            self.abuse_client = AbuseIPDBClient(os.getenv("ABUSEIPDB_API_KEY"))
        if os.getenv("ALIENVAULT_API_KEY"):
            self.otx_client = AlienVaultClient(os.getenv("ALIENVAULT_API_KEY"))
        if os.getenv("VIRUSTOTAL_API_KEY"):
            self.vt_client = VirusTotalClient(os.getenv("VIRUSTOTAL_API_KEY"))

        self.last_update = None
        self.cached_data = {}
        self.cache_duration = timedelta(minutes=5)
        self.storage = ThreatStorage()

    def is_cache_valid(self) -> bool:
        if not self.last_update:
            return False
        return datetime.now() - self.last_update < self.cache_duration

    def get_aggregated_threat_data(self, force_refresh: bool = False) -> Dict:
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
            "statistics": {
                "by_source": {},
                "by_type": {},
                "timeline": {}
            },
            "risk": {},
            "correlations": [],
            "top_lists": {},
            "geo": {},
            "campaigns": {},
            "health": {},
            "alerts": []
        }

        # AbuseIPDB
        if self.abuse_client:
            try:
                aggregated_data["connections"]["abuseipdb"] = self.abuse_client.test_connection()
                if aggregated_data["connections"]["abuseipdb"].get("online") is True and aggregated_data["connections"]["abuseipdb"].get("warning") != "rate_limited":
                    abuse_data = self.abuse_client.get_threat_stats()
                    aggregated_data["sources"]["abuseipdb"] = abuse_data
                else:
                    aggregated_data["sources"]["abuseipdb"] = {"error": "Data temporarily unavailable", "source": "AbuseIPDB"}

                if "abuse_data" in locals() and "error" not in abuse_data:
                    aggregated_data["summary"]["total_threats"] += abuse_data.get("total_reports", 0)
                    aggregated_data["summary"]["high_risk_indicators"] += abuse_data.get("last_24h_reports", 0)

                    aggregated_data["statistics"]["by_source"]["abuseipdb"] = {
                        "reports": abuse_data.get("total_reports", 0),
                        "last_24h": abuse_data.get("last_24h_reports", 0),
                        "last_7d": abuse_data.get("last_7d_reports", 0)
                    }

                    top_categories = abuse_data.get("top_categories", {})
                    for category, count in list(top_categories.items())[:5]:
                        aggregated_data["summary"]["trending_threats"].append({
                            "type": "category",
                            "name": str(category),
                            "count": count,
                            "source": "abuseipdb"
                        })

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

        # AlienVault OTX
        if self.otx_client:
            try:
                aggregated_data["connections"]["alienvault"] = self.otx_client.test_connection()
                if aggregated_data["connections"]["alienvault"].get("online") is True and aggregated_data["connections"]["alienvault"].get("warning") != "rate_limited":
                    otx_data = self.otx_client.get_threat_stats()
                    aggregated_data["sources"]["alienvault"] = otx_data
                else:
                    aggregated_data["sources"]["alienvault"] = {"error": "Data temporarily unavailable", "source": "AlienVault OTX"}

                if "otx_data" in locals() and "error" not in otx_data:
                    aggregated_data["summary"]["total_threats"] += otx_data.get("total_pulses", 0)
                    aggregated_data["summary"]["active_campaigns"] += otx_data.get("total_pulses", 0)

                    aggregated_data["statistics"]["by_source"]["alienvault"] = {
                        "pulses": otx_data.get("total_pulses", 0),
                        "indicators": otx_data.get("total_indicators", 0),
                        "last_24h": otx_data.get("last_24h_pulses", 0),
                        "last_7d": otx_data.get("last_7d_pulses", 0)
                    }

                    top_tags = otx_data.get("top_tags", {})
                    for tag, count in list(top_tags.items())[:5]:
                        aggregated_data["summary"]["trending_threats"].append({
                            "type": "tag",
                            "name": str(tag),
                            "count": count,
                            "source": "alienvault"
                        })

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

        # VirusTotal
        if self.vt_client:
            try:
                aggregated_data["connections"]["virustotal"] = self.vt_client.test_connection()
                vt_data = self.vt_client.get_threat_stats()
                aggregated_data["sources"]["virustotal"] = vt_data

                if "error" not in vt_data:
                    scan_dist = vt_data.get("scan_distribution", {})
                    malicious_count = scan_dist.get("malicious", 0)
                    suspicious_count = scan_dist.get("suspicious", 0)

                    aggregated_data["summary"]["high_risk_indicators"] += malicious_count + suspicious_count
                    aggregated_data["statistics"]["by_source"]["virustotal"] = scan_dist

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

        # Indicator collection and correlation
        abuse_blacklist = None
        if self.abuse_client and aggregated_data["connections"].get("abuseipdb", {}).get("online") is True:
            abuse_blacklist = self.abuse_client.get_blacklist(limit=200)
        otx_pulses = None
        if self.otx_client and aggregated_data["connections"].get("alienvault", {}).get("online") is True:
            otx_pulses = self.otx_client.get_pulses(limit=50)

        indicators = self._collect_indicators(abuse_blacklist, otx_pulses)
        correlations = self._correlate_indicators(indicators)
        top_lists = self._build_top_lists(correlations)
        geo = self._collect_geo(abuse_blacklist)
        campaigns = self._collect_campaigns(otx_pulses)

        aggregated_data["correlations"] = correlations
        aggregated_data["top_lists"] = top_lists
        aggregated_data["geo"] = geo
        aggregated_data["campaigns"] = campaigns

        aggregated_data["risk"] = self._calculate_risk_score(aggregated_data, geo)
        aggregated_data["health"] = self._collect_health(aggregated_data["connections"])

        # Sort alerts by severity
        alert_levels = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        aggregated_data["alerts"].sort(key=lambda x: alert_levels.get(x["level"], 0), reverse=True)
        aggregated_data["alerts"] = aggregated_data["alerts"][:10]

        aggregated_data["summary"]["trending_threats"].sort(key=lambda x: x["count"], reverse=True)
        aggregated_data["summary"]["trending_threats"] = aggregated_data["summary"]["trending_threats"][:10]

        self.cached_data = aggregated_data
        self.last_update = datetime.now()
        self._store_summary(aggregated_data)

        return aggregated_data

    def get_threat_timeline(self, days: int = 7) -> Dict:
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

        return timeline

    def get_history(self, days: int = 7) -> List[Dict]:
        return self.storage.get_summary_history(days=days)

    def search_indicators(self, query: str, indicator_type: str = "all") -> Dict:
        results = {
            "query": query,
            "type": indicator_type,
            "results": {},
            "timestamp": datetime.now().isoformat()
        }
        normalized_query = (query or "").strip()
        inferred_type = self._infer_indicator_type(normalized_query)
        effective_type = inferred_type if indicator_type == "all" else indicator_type

        if self.abuse_client and effective_type == "ip":
            try:
                ip_result = self.abuse_client.check_ip(normalized_query)
                results["results"]["abuseipdb"] = ip_result
            except Exception as e:
                results["results"]["abuseipdb"] = {"error": str(e)}

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

        if self.vt_client:
            try:
                if effective_type in ["url"]:
                    vt_result = self.vt_client.get_url_report(normalized_query)
                    results["results"]["virustotal"] = vt_result
                elif effective_type in ["ip"]:
                    vt_result = self.vt_client.get_ip_report(normalized_query)
                    results["results"]["virustotal"] = vt_result
                elif effective_type in ["domain"]:
                    vt_result = self.vt_client.get_domain_report(normalized_query)
                    results["results"]["virustotal"] = vt_result
                elif effective_type in ["hash"]:
                    vt_result = self.vt_client.get_file_report(normalized_query)
                    results["results"]["virustotal"] = vt_result
            except Exception as e:
                results["results"]["virustotal"] = {"error": str(e)}

        results["risk"] = self._score_query(results.get("results", {}))
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

    def _score_query(self, result_map: Dict) -> Dict:
        score = 0
        sources = 0
        if "abuseipdb" in result_map and isinstance(result_map.get("abuseipdb"), dict):
            data = result_map["abuseipdb"].get("data", {})
            if isinstance(data, dict):
                score += min(100, int(data.get("abuseConfidenceScore", 0)))
                sources += 1
        if "virustotal" in result_map and isinstance(result_map.get("virustotal"), dict):
            vt = result_map["virustotal"]
            positives = int(vt.get("positives", 0) or 0)
            total = int(vt.get("total", 0) or 0)
            if total > 0:
                score += min(100, int((positives / total) * 100))
                sources += 1
        if "alienvault" in result_map and isinstance(result_map.get("alienvault"), dict):
            pulse_info = result_map["alienvault"].get("pulse_info", {})
            if isinstance(pulse_info, dict):
                pulse_count = int(pulse_info.get("count", 0) or 0)
                score += min(100, pulse_count * 10)
                sources += 1
        if sources == 0:
            return {"score": 0, "severity": "Low"}
        avg_score = int(score / sources)
        return {"score": avg_score, "severity": self._severity_label(avg_score)}

    @staticmethod
    def _severity_label(score: int) -> str:
        if score >= 75:
            return "Critical"
        if score >= 50:
            return "High"
        if score >= 25:
            return "Medium"
        return "Low"

    def _calculate_risk_score(self, aggregated_data: Dict, geo: Dict) -> Dict:
        abuse_last24h = aggregated_data.get("statistics", {}).get("by_source", {}).get("abuseipdb", {}).get("last_24h", 0)
        otx_last24h = aggregated_data.get("statistics", {}).get("by_source", {}).get("alienvault", {}).get("last_24h", 0)
        vt_malicious = aggregated_data.get("statistics", {}).get("by_source", {}).get("virustotal", {}).get("malicious", 0)
        geo_count = len(geo.get("by_country", {}))

        def scaled(value: int, max_value: int) -> int:
            if max_value <= 0:
                return 0
            return min(100, int((value / max_value) * 100))

        abuse_score = scaled(abuse_last24h, 200)
        otx_score = scaled(otx_last24h, 20)
        vt_score = scaled(vt_malicious, 20)
        geo_score = scaled(geo_count, 20)

        score = int((abuse_score * 0.4) + (otx_score * 0.3) + (vt_score * 0.2) + (geo_score * 0.1))
        return {
            "score": score,
            "severity": self._severity_label(score),
            "components": {
                "abuse": abuse_score,
                "otx": otx_score,
                "virustotal": vt_score,
                "geography": geo_score
            }
        }

    def _collect_health(self, connections: Dict) -> Dict:
        health = {}
        for source, conn in connections.items():
            if not isinstance(conn, dict):
                continue
            response_time = conn.get("response_time")
            if response_time is None:
                response_ms = None
            else:
                response_ms = int(response_time * 1000)
            health[source] = {
                "online": conn.get("online") is True,
                "warning": conn.get("warning"),
                "response_ms": response_ms,
                "error": conn.get("error")
            }
        return health

    def _collect_indicators(self, abuse_blacklist: Optional[Dict], otx_pulses: Optional[Dict]) -> List[Dict]:
        indicators: List[Dict] = []
        if isinstance(abuse_blacklist, dict):
            for entry in abuse_blacklist.get("data", []) or []:
                if not isinstance(entry, dict):
                    continue
                indicators.append({
                    "type": "ip",
                    "value": entry.get("ipAddress"),
                    "score": int(entry.get("abuseConfidenceScore", 0) or 0),
                    "source": "abuseipdb",
                    "last_seen": entry.get("lastReportedAt"),
                    "meta": {
                        "reports": entry.get("totalReports", 0),
                        "country": entry.get("countryCode")
                    }
                })
        if isinstance(otx_pulses, dict):
            for pulse in otx_pulses.get("results", []) or []:
                for ind in pulse.get("indicators", []) or []:
                    ind_value = ind.get("indicator") or ind.get("value")
                    ind_type = (ind.get("type") or "").lower()
                    mapped_type = self._map_otx_type(ind_type)
                    if not ind_value or not mapped_type:
                        continue
                    indicators.append({
                        "type": mapped_type,
                        "value": ind_value,
                        "score": 70,
                        "source": "alienvault",
                        "last_seen": pulse.get("created"),
                        "meta": {
                            "pulse": pulse.get("name"),
                            "tags": pulse.get("tags", [])
                        }
                    })
        return indicators

    @staticmethod
    def _map_otx_type(ind_type: str) -> Optional[str]:
        if "ipv4" in ind_type or ind_type == "ip":
            return "ip"
        if ind_type in ["domain", "hostname"]:
            return "domain"
        if ind_type == "url":
            return "url"
        if "filehash" in ind_type or ind_type in ["file", "hash"]:
            return "hash"
        return None

    def _correlate_indicators(self, indicators: List[Dict]) -> List[Dict]:
        by_key: Dict[str, Dict] = {}
        for ind in indicators:
            key = f"{ind.get('type')}:{ind.get('value')}"
            if key not in by_key:
                by_key[key] = {
                    "type": ind.get("type"),
                    "value": ind.get("value"),
                    "sources": set(),
                    "score": ind.get("score", 0),
                    "last_seen": ind.get("last_seen"),
                    "meta": []
                }
            entry = by_key[key]
            entry["sources"].add(ind.get("source"))
            entry["score"] = max(entry["score"], ind.get("score", 0))
            entry["meta"].append(ind.get("meta", {}))
            if ind.get("last_seen") and (entry["last_seen"] is None or ind.get("last_seen") > entry["last_seen"]):
                entry["last_seen"] = ind.get("last_seen")

        correlated = []
        for entry in by_key.values():
            sources = sorted([s for s in entry["sources"] if s])
            correlated.append({
                "type": entry["type"],
                "value": entry["value"],
                "sources": sources,
                "score": entry["score"],
                "last_seen": entry["last_seen"],
                "correlation_count": len(sources)
            })
        correlated.sort(key=lambda x: (x["correlation_count"], x["score"]), reverse=True)
        return correlated[:200]

    def _build_top_lists(self, correlations: List[Dict]) -> Dict:
        top_lists = {"ip": [], "domain": [], "url": [], "hash": []}
        for item in correlations:
            item_type = item.get("type")
            if item_type in top_lists:
                top_lists[item_type].append(item)
        for key in top_lists:
            top_lists[key] = sorted(top_lists[key], key=lambda x: (x["score"], x["correlation_count"]), reverse=True)[:10]
        return top_lists

    def _collect_geo(self, abuse_blacklist: Optional[Dict]) -> Dict:
        by_country = defaultdict(int)
        if isinstance(abuse_blacklist, dict):
            for entry in abuse_blacklist.get("data", []) or []:
                country = entry.get("countryCode") or "UN"
                by_country[country] += 1
        return {"by_country": dict(by_country)}

    def _collect_campaigns(self, otx_pulses: Optional[Dict]) -> Dict:
        if not isinstance(otx_pulses, dict):
            return {}
        tags = defaultdict(int)
        authors = defaultdict(int)
        recent = []
        for pulse in otx_pulses.get("results", []) or []:
            for tag in pulse.get("tags", []) or []:
                tags[tag] += 1
            author = pulse.get("author_name") or "Unknown"
            authors[author] += 1
            recent.append({
                "name": pulse.get("name"),
                "created": pulse.get("created"),
                "indicators": len(pulse.get("indicators", []) or []),
                "tags": pulse.get("tags", [])[:5]
            })
        return {
            "top_tags": dict(sorted(tags.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_authors": dict(sorted(authors.items(), key=lambda x: x[1], reverse=True)[:5]),
            "recent_pulses": recent[:10]
        }

    def _store_summary(self, aggregated_data: Dict) -> None:
        summary = aggregated_data.get("summary", {})
        stats = aggregated_data.get("statistics", {}).get("by_source", {})
        risk = aggregated_data.get("risk", {})
        sources_online = len([s for s in aggregated_data.get("connections", {}).values() if isinstance(s, dict) and s.get("online") is True])
        self.storage.insert_summary({
            "timestamp": aggregated_data.get("timestamp"),
            "total_threats": summary.get("total_threats", 0),
            "high_risk_indicators": summary.get("high_risk_indicators", 0),
            "active_campaigns": summary.get("active_campaigns", 0),
            "sources_online": sources_online,
            "abuse_last24h": stats.get("abuseipdb", {}).get("last_24h", 0),
            "otx_last24h": stats.get("alienvault", {}).get("last_24h", 0),
            "vt_malicious": stats.get("virustotal", {}).get("malicious", 0),
            "risk_score": risk.get("score", 0)
        })
