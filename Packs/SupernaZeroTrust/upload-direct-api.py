#!/usr/bin/env python3
"""
Direct XSOAR REST API Upload Script
Bypasses demisto-sdk authentication issues
"""

import requests
import json
import sys
from pathlib import Path

# Configuration
BASE_URL = "https://api-superna.crtx.ca.paloaltonetworks.com"
API_KEY = "afoeACCMPL6HpbcoH2Q71AeqrLAbVh7sY4xkfy6IuHCDj8zBcvGxLeWumYBrJHSOMjKjfA78TfbHdMNtjGSg6t9pK9pHKV2pHFkOOJtoizfIhvbBdJO50yjFLenpKikU"
AUTH_ID = "2"

# Integration files
INTEGRATION_DIR = Path(__file__).parent / "Integrations" / "SupernaZeroTrust"
INTEGRATION_YML = INTEGRATION_DIR / "SupernaZeroTrust.yml"
INTEGRATION_PY = INTEGRATION_DIR / "SupernaZeroTrust.py"

def upload_integration():
    """Upload integration using XSOAR REST API"""

    print("=" * 80)
    print("XSOAR Direct API Upload")
    print("=" * 80)

    # Read integration files
    print("\n[1/4] Reading integration files...")
    try:
        with open(INTEGRATION_YML, 'r') as f:
            yml_content = f.read()
        with open(INTEGRATION_PY, 'r') as f:
            py_content = f.read()
        print("✅ Files read successfully")
    except Exception as e:
        print(f"❌ Error reading files: {e}")
        return False

    # Prepare headers
    print("\n[2/4] Preparing API request...")
    headers = {
        "Authorization": API_KEY,
        "x-xdr-auth-id": AUTH_ID,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # Prepare payload (try automation endpoint)
    payload = {
        "name": "SupernaZeroTrust",
        "script": py_content,
        "type": "python",
        "tags": ["superna", "zerotrust", "ransomware"],
        "comment": "Superna Zero Trust Integration for ransomware protection"
    }

    # Try to upload
    print(f"\n[3/4] Uploading to {BASE_URL}...")

    # Try different API endpoints
    endpoints = [
        "/automation/load",
        "/automation/save",
        "/integration/upload",
        "/playbook/save"
    ]

    for endpoint in endpoints:
        url = f"{BASE_URL}{endpoint}"
        print(f"\nTrying endpoint: {endpoint}")

        try:
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                verify=True,
                timeout=30
            )

            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text[:200]}")

            if response.status_code == 200:
                print(f"\n✅ SUCCESS! Integration uploaded via {endpoint}")
                return True
            elif response.status_code == 401:
                print(f"❌ 401 Unauthorized - Authentication failed")
            elif response.status_code == 404:
                print(f"⚠️  404 Not Found - Endpoint doesn't exist")
            else:
                print(f"⚠️  {response.status_code} - {response.reason}")

        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")

    print("\n[4/4] All endpoints failed")
    return False

if __name__ == "__main__":
    print("\nXSOAR Direct API Upload Tool")
    print("This bypasses demisto-sdk authentication issues\n")

    success = upload_integration()

    if success:
        print("\n" + "=" * 80)
        print("✅ UPLOAD SUCCESSFUL!")
        print("=" * 80)
        sys.exit(0)
    else:
        print("\n" + "=" * 80)
        print("❌ UPLOAD FAILED - See errors above")
        print("=" * 80)
        print("\nRECOMMENDATION:")
        print("Contact Palo Alto Networks support about SDK authentication issues")
        print("Or use the manual UI upload method")
        sys.exit(1)
