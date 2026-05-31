#!/usr/bin/env python3
"""
UCP Salesforce Instance Creator

Creates a Salesforce connector instance via the UCP Shell API.
Only enables the "automation-and-remediation" capability with OAuth2 Client Credentials.

Prerequisites:
  1. Request permissions in #xdr-permissions-dev Slack channel
  2. gcloud CLI and kubectl must be installed and authenticated
"""

import atexit
import json
import os
import signal
import socket
import subprocess
import sys
import time
import uuid

import demisto_client
import requests
from dotenv import load_dotenv

from main import get_instances_by_brand

load_dotenv()

# ============================================================
# Configuration — Edit these values before running
# ============================================================
TENANT_ID = os.getenv("UCP_TENANT_ID", "")
CONNECTOR_ID = os.getenv("UCP_CONNECTOR_ID", "salesforce")
INSTANCE_NAME = f"Salesforce Test {uuid.uuid4().hex[:8]}"
DOMAIN_URL = "test.salesforce.com"  
CLIENT_KEY = "test_client_key"  # Placeholder, will be overridden by .env value
CLIENT_SECRET = "test_client_secret"  # Placeholder, will be overridden by .env value
PORT = int(os.getenv("UCP_PORT", "8080"))
BASE_URL = f"http://localhost:{PORT}/api/v1"

# Only this capability will be enabled
SELECTED_CAPABILITY = "automation-and-remediation"
# Profile to use for authentication
PROFILE_ID = "oauth2_client_credentials.salesforce"

# GKE cluster details
GKE_ZONE = "us-central1-f"
GKE_PROJECT = f"qa2-test-{TENANT_ID}"
GKE_CLUSTER = f"cluster-{TENANT_ID}"
K8S_NAMESPACE = "xdr-st"
K8S_APP_LABEL = f"xdr-st-{TENANT_ID}-unified-connector-shell"

# XSOAR tenant connection (for verifying XSOAR instances)
XSOAR_BASE_URL = os.getenv("DEMISTO_BASE_URL")
XSOAR_API_KEY = os.getenv("DEMISTO_API_KEY")
XSOAR_AUTH_ID = os.getenv("XSIAM_AUTH_ID")
XSOAR_BRAND_NAME = "Salesforce IAM"  # The XSOAR brand/integration name to look for

# Port-forward process handle
_port_forward_proc = None


def _cleanup_port_forward():
    """Terminate the port-forward subprocess if it's still running."""
    global _port_forward_proc
    if _port_forward_proc and _port_forward_proc.poll() is None:
        _port_forward_proc.terminate()
        try:
            _port_forward_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _port_forward_proc.kill()
        print("   🔌 Port-forward stopped.")


def _wait_for_port(port, timeout=30):
    """Wait until localhost:port is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def start_port_forward():
    """Get GKE credentials and start kubectl port-forward as a background process."""
    global _port_forward_proc

    print("🔑 Getting GKE credentials...")
    result = subprocess.run(
        [
            "gcloud", "container", "clusters", "get-credentials",
            GKE_CLUSTER, "--zone", GKE_ZONE, "--project", GKE_PROJECT,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"   ❌ Failed to get GKE credentials:\n{result.stderr}")
        sys.exit(1)
    print("   ✅ GKE credentials configured.")

    print(f"🔌 Starting port-forward (localhost:{PORT} → shell pod:{PORT})...")

    # Discover the pod name
    pod_result = subprocess.run(
        [
            "kubectl", "get", "pod",
            "--namespace", K8S_NAMESPACE,
            f"--selector=app={K8S_APP_LABEL}",
            "--output", "jsonpath={.items[0].metadata.name}",
        ],
        capture_output=True,
        text=True,
    )
    if pod_result.returncode != 0 or not pod_result.stdout.strip():
        print(f"   ❌ Failed to find shell pod:\n{pod_result.stderr}")
        sys.exit(1)

    pod_name = pod_result.stdout.strip()
    print(f"   📦 Pod: {pod_name}")

    _port_forward_proc = subprocess.Popen(
        [
            "kubectl", "port-forward",
            "--namespace", K8S_NAMESPACE,
            pod_name,
            f"{PORT}:{PORT}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    # Ensure cleanup on exit
    atexit.register(_cleanup_port_forward)
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    if not _wait_for_port(PORT):
        stderr = _port_forward_proc.stderr.read().decode() if _port_forward_proc.stderr else ""
        print(f"   ❌ Port-forward did not become ready within 30s.\n{stderr}")
        sys.exit(1)

    print(f"   ✅ Port-forward ready on localhost:{PORT}")
    print()


def main():
    print("🔧 UCP Salesforce Instance Creator")
    print("━" * 50)
    print()

    # Validate required env vars
    required_vars = {
        "UCP_TENANT_ID": TENANT_ID,
        "UCP_DOMAIN_URL": DOMAIN_URL,
        "UCP_CLIENT_KEY": CLIENT_KEY,
        "UCP_CLIENT_SECRET": CLIENT_SECRET,
    }
    missing = [name for name, val in required_vars.items() if not val]
    if missing:
        print(f"❌ Missing required environment variables: {', '.join(missing)}")
        print("   Set them in .env or as environment variables before running.")
        sys.exit(1)

    # Prerequisites reminder
    print("⚠️  Prerequisites:")
    print(f"    1. Request permissions in #xdr-permissions-dev:")
    print(f'       permissions role=xsoar-content-tier1, project={GKE_PROJECT}, reason=port forwarding for testing, approver=<your username>')
    print()

    try:
        input("    Press Enter to continue (or Ctrl+C to abort)... ")
    except KeyboardInterrupt:
        print("\n    Aborted.")
        sys.exit(0)

    print()

    # ── Start port-forward ─────────────────────────────────
    start_port_forward()

    # ── Step 1: Get Creation View ──────────────────────────
    print("📋 Step 1: Getting creation view...")
    try:
        resp = requests.get(
            f"{BASE_URL}/gateway/connectors/{CONNECTOR_ID}/creation",
            headers={"x-tenant-id": TENANT_ID},
        )
    except requests.ConnectionError:
        print("   ❌ Connection failed. Is port-forwarding running?")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"   ❌ Failed with status {resp.status_code}")
        print(f"   Response: {resp.text}")
        sys.exit(1)

    creation_view = resp.json()
    instance_id = creation_view["instance_id"]
    print(f"   ✅ Instance ID pre-allocated: {instance_id}")

    # Extract capabilities
    capabilities_step = creation_view["steps"][0]
    available_caps = [c["id"] for c in capabilities_step.get("capabilities", [])]
    print(f"   📦 Available capabilities: {available_caps}")

    if SELECTED_CAPABILITY not in available_caps:
        print(f"   ❌ Capability '{SELECTED_CAPABILITY}' not found in available capabilities!")
        sys.exit(1)
    print(f"   ✅ Using capability: {SELECTED_CAPABILITY}")

    # Extract connection methods and find applied_for IDs
    connection_step = creation_view["steps"][1]
    methods = connection_step.get("methods", [])

    applied_for = []
    for method in methods:
        if method.get("capability_id") != SELECTED_CAPABILITY:
            continue
        # Check if this method supports our profile
        options = method.get("options", [])
        for opt in options:
            if opt.get("profile_id") == PROFILE_ID:
                applied_for.append(method["method_unique_id"])
                break

    print(f"   🔌 Methods matched for {PROFILE_ID}: {len(applied_for)}")
    for mid in applied_for:
        print(f"      • {mid}")

    if not applied_for:
        print(f"   ❌ No methods found for capability '{SELECTED_CAPABILITY}' with profile '{PROFILE_ID}'!")
        sys.exit(1)

    # Extract configuration defaults for selected capability
    config_step = creation_view["steps"][2]
    configuration = {}
    for section in config_step.get("sections", []):
        if section.get("capability_id") != SELECTED_CAPABILITY:
            continue
        for row in section.get("data", []):
            for field in row.get("fields", []):
                field_id = field.get("id")
                default_val = field.get("options", {}).get("default_value")
                if field_id and default_val is not None:
                    configuration[field_id] = default_val

    print(f"   ⚙️  Configuration defaults: {len(configuration)} fields")
    for k, v in configuration.items():
        print(f"      • {k}: {v}")

    print()

    # ── Step 2: Create Instance ────────────────────────────
    print(f'📋 Step 2: Creating instance "{INSTANCE_NAME}"...')

    payload = {
        "instance_id": instance_id,
        "connector_id": CONNECTOR_ID,
        "capabilities": {
            "general_configurations": {
                "instance_name": INSTANCE_NAME,
            },
            "values": {
                SELECTED_CAPABILITY: [],
            },
        },
        "connection": {
            "origin": "RECOMMENDED",
            "general_configurations": {
                "domain": DOMAIN_URL,
            },
            "profiles": [
                {
                    "profile_id": PROFILE_ID,
                    "type": "oauth2_client_credentials",
                    "applied_for": applied_for,
                    "values": {
                        "client_key": CLIENT_KEY,
                        "client_secret": CLIENT_SECRET,
                    },
                }
            ],
        },
        "configuration": configuration,
    }

    print("   Payload:")
    print(json.dumps(payload, indent=4))
    print()

    resp = requests.post(
        f"{BASE_URL}/instances",
        headers={"x-tenant-id": TENANT_ID, "Content-Type": "application/json"},
        json=payload,
    )

    if resp.status_code == 201:
        result = resp.json()
        print("   ✅ Instance created successfully!")
        print(f"      ID:     {result.get('id')}")
        print(f"      Name:   {result.get('name')}")
        print(f"      Status: {result.get('status')}")
    else:
        print(f"   ❌ Failed with status {resp.status_code}")
        print(f"   Response: {resp.text}")
        sys.exit(1)

    print()

    # ── Step 3: Verify XSOAR Instance ──────────────────────
    print("📋 Step 3: Verifying XSOAR integration instance...")
    
    if not all([XSOAR_BASE_URL, XSOAR_API_KEY, XSOAR_AUTH_ID]):
        print("   ⚠️  Skipping XSOAR verification — missing DEMISTO_BASE_URL, DEMISTO_API_KEY, or XSIAM_AUTH_ID in .env")
    else:
        print(f"   Connecting to XSOAR tenant: {XSOAR_BASE_URL}")
        xsoar_client = demisto_client.configure(
            base_url=XSOAR_BASE_URL,
            api_key=XSOAR_API_KEY,
            auth_id=XSOAR_AUTH_ID,
            verify_ssl=False,
        )
        
        # Poll for the XSOAR instance to appear (it may take a few seconds)
        max_retries = 10
        poll_interval = 3
        found_instances = []
        
        for attempt in range(1, max_retries + 1):
            print(f"   🔍 Checking for XSOAR instance with brand '{XSOAR_BRAND_NAME}' (attempt {attempt}/{max_retries})...")
            found_instances = get_instances_by_brand(xsoar_client, XSOAR_BRAND_NAME)
            if found_instances:
                break
            if attempt < max_retries:
                print(f"   ⏳ Not found yet, waiting {poll_interval}s...")
                time.sleep(poll_interval)
        
        if found_instances:
            print(f"   ✅ Found {len(found_instances)} XSOAR instance(s) for brand '{XSOAR_BRAND_NAME}':")
            for inst in found_instances:
                inst_name = inst.get("name", "unknown")
                inst_id = inst.get("id", "unknown")
                inst_enabled = inst.get("enabled", "unknown")
                print(f"      • Name: {inst_name}")
                print(f"        ID: {inst_id}")
                print(f"        Enabled: {inst_enabled}")
        else:
            print(f"   ❌ No XSOAR instance found for brand '{XSOAR_BRAND_NAME}' after {max_retries * poll_interval}s")
    
    print()

    # ── Step 4: Cleanup ────────────────────────────────────
    try:
        answer = input("🗑️  Cleanup: Delete the created instance? (y/N): ")
    except KeyboardInterrupt:
        print("\n   Skipping cleanup.")
        return

    if answer.strip().lower() == "y":
        resp = requests.delete(
            f"{BASE_URL}/instances/{instance_id}",
            headers={"x-tenant-id": TENANT_ID},
        )
        if resp.status_code == 204:
            print("   ✅ Instance deleted successfully!")
        else:
            print(f"   ❌ Delete failed with status {resp.status_code}")
            print(f"   Response: {resp.text}")
    else:
        print("   Skipping cleanup. Instance kept.")


if __name__ == "__main__":
    main()
