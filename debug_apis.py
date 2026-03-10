#!/usr/bin/env python3
"""
Debug script to test API responses from threat intelligence sources
"""

import os
import requests
from dotenv import load_dotenv

def test_abuseipdb():
    load_dotenv()
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        print("❌ ABUSEIPDB_API_KEY not found")
        return

    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "limit": 10,
        "confidenceMinimum": 75
    }

    print("🔍 Testing AbuseIPDB /blacklist API...")
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Content-Type: {response.headers.get('Content-Type')}")
        print(f"Response: {response.text[:500]}...")
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"✅ JSON data: {data.keys()}")
                if "data" in data:
                    print(f"✅ Data type: {type(data['data'])}, length: {len(data['data']) if data['data'] else 0}")
                else:
                    print("❌ No 'data' key")
            except:
                print("❌ Response is not JSON")
        else:
            print(f"❌ HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_alienvault():
    load_dotenv()
    api_key = os.getenv("ALIENVAULT_API_KEY")

    if not api_key:
        print("❌ ALIENVAULT_API_KEY not found")
        return

    url = "https://otx.alienvault.com/api/v1/pulses"
    headers = {
        "X-OTX-API-KEY": api_key
    }
    params = {"limit": 10}

    print("🔍 Testing AlienVault OTX API...")
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:500]}...")
        if response.status_code == 200:
            data = response.json()
            if "results" in data:
                print(f"✅ Results found: {len(data['results'])} pulses")
            else:
                print("❌ No 'results' key in response")
        else:
            print(f"❌ HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("🛡️ Testing Threat Intelligence APIs\n")
    test_abuseipdb()
    print()
    test_alienvault()
