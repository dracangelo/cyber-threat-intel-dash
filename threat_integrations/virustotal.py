import requests
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {}
    
    def get_file_report(self, resource: str) -> Dict:
        """Get file scan report"""
        url = f"{self.base_url}/file/report"
        params = {
            "apikey": self.api_key,
            "resource": resource
        }
        
        try:
            response = requests.post(url, params=params, timeout=20)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def scan_file(self, file_path: str) -> Dict:
        """Scan a file (requires file upload)"""
        url = f"{self.base_url}/file/scan"
        
        try:
            with open(file_path, 'rb') as file:
                files = {'file': file}
                params = {'apikey': self.api_key}
                response = requests.post(url, files=files, params=params, timeout=60)
                response.raise_for_status()
                return response.json()
        except Exception as e:
            return {"error": str(e), "data": None}
    
    def get_url_report(self, resource: str, scan: int = 0) -> Dict:
        """Get URL scan report"""
        url = f"{self.base_url}/url/report"
        params = {
            "apikey": self.api_key,
            "resource": resource,
            "scan": scan
        }
        
        try:
            response = requests.post(url, params=params, timeout=20)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def scan_url(self, url: str) -> Dict:
        """Scan a URL"""
        scan_url = f"{self.base_url}/url/scan"
        params = {
            "apikey": self.api_key,
            "url": url
        }
        
        try:
            response = requests.post(scan_url, params=params, timeout=20)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_ip_report(self, ip: str) -> Dict:
        """Get IP address report"""
        url = f"{self.base_url}/ip-address/report"
        params = {
            "apikey": self.api_key,
            "ip": ip
        }
        
        try:
            response = requests.get(url, params=params, timeout=20)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_domain_report(self, domain: str) -> Dict:
        """Get domain report"""
        url = f"{self.base_url}/domain/report"
        params = {
            "apikey": self.api_key,
            "domain": domain
        }
        
        try:
            response = requests.get(url, params=params, timeout=20)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_comments(self, resource: str, before: Optional[str] = None) -> Dict:
        """Get comments for a resource"""
        url = f"{self.base_url}/comments/get"
        params = {
            "apikey": self.api_key,
            "resource": resource
        }
        
        if before:
            params["before"] = before
        
        try:
            response = requests.get(url, params=params, timeout=20)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}
    
    def get_threat_stats(self) -> Dict:
        """Get threat statistics for dashboard"""
        try:
            # Get recent file reports (this is a simplified approach)
            # In a real implementation, you might want to use VirusTotal's premium API
            # for more comprehensive statistics
            
            # For demo purposes, we'll create mock statistics based on typical VT data
            # In production, you'd want to track your own scanned files/URLs
            
            stats = {
                "total_scans_today": 0,  # Would need to track this
                "malicious_detections": 0,  # Would need to track this
                "top_malware_families": {},  # Would need to track this
                "top_malicious_domains": {},  # Would need to track this
                "scan_distribution": {
                    "clean": 0,
                    "suspicious": 0,
                    "malicious": 0
                },
                "source": "VirusTotal"
            }
            
            # For demonstration, we'll scan a few known safe/malicious samples
            test_urls = [
                "https://www.google.com",  # Safe
                "http://malware.wicar.org/testmalware.exe"  # Test malware
            ]
            
            clean_count = 0
            malicious_count = 0
            suspicious_count = 0
            
            for test_url in test_urls:
                report = self.get_url_report(test_url)
                if "positives" in report:
                    positives = report["positives"]
                    total = report["total"]
                    
                    if positives == 0:
                        clean_count += 1
                    elif positives >= total // 2:
                        malicious_count += 1
                    else:
                        suspicious_count += 1
            
            stats["scan_distribution"] = {
                "clean": clean_count,
                "suspicious": suspicious_count,
                "malicious": malicious_count
            }
            
            return stats
            
        except Exception as e:
            return {"error": str(e), "source": "VirusTotal"}
