#!/usr/bin/env python3
"""
Demisto Lock Stress Test
========================
Reproduces the lost-update race condition in demisto-lock-release (XSUP-67021).

How it works:
  1. Creates N incidents via the XSOAR REST API.
  2. Runs the "DemistoLock - Hello World Demo" playbook on all of them simultaneously.
  3. After all playbooks finish, calls demisto-lock-info to check for stuck locks.
  4. Reports how many locks were left stuck (the bug) vs. fully released (the fix).

Usage:
  pip install requests
  python stress_test_lock.py --url https://your-xsoar-instance --api-key YOUR_API_KEY --incidents 20

Requirements:
  - XSOAR 8.x
  - Demisto Lock integration installed and enabled
  - "DemistoLock - Hello World Demo" playbook imported (or use --playbook to specify another)
"""

import argparse
import concurrent.futures
import json
import time
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Demisto Lock stress test (XSUP-67021)")
    parser.add_argument("--url", required=True, help="XSOAR base URL, e.g. https://xsoar.example.com")
    parser.add_argument("--api-key", required=True, help="XSOAR API key")
    parser.add_argument("--incidents", type=int, default=20, help="Number of concurrent incidents (default: 20)")
    parser.add_argument("--playbook", default="DemistoLock - Hello World Demo",
                        help="Playbook name to run on each incident")
    parser.add_argument("--lock-name", default="stress-test-lock",
                        help="Lock name to use (default: stress-test-lock)")
    parser.add_argument("--wait-seconds", type=int, default=120,
                        help="Seconds to wait for all playbooks to finish (default: 120)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    return parser.parse_args()


class XSOARClient:
    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.verify = verify_ssl

    def _post(self, path: str, body: dict) -> dict:
        resp = self.session.post(f"{self.base_url}{path}", json=body, verify=self.verify)
        resp.raise_for_status()
        return resp.json()

    def _get(self, path: str) -> dict:
        resp = self.session.get(f"{self.base_url}{path}", verify=self.verify)
        resp.raise_for_status()
        return resp.json()

    def create_incident(self, name: str, playbook: str) -> str:
        """Create an incident and return its ID."""
        body = {
            "name": name,
            "playbookId": playbook,
            "type": "Unclassified",
        }
        result = self._post("/incident", body)
        return str(result["id"])

    def run_command(self, incident_id: str, command: str, args: dict | None = None) -> dict:
        """Execute a CLI command in the context of an incident."""
        body = {
            "investigationId": incident_id,
            "data": command,
            "args": args or {},
        }
        return self._post("/entry/execute/sync", body)

    def get_incident(self, incident_id: str) -> dict:
        return self._get(f"/incident/{incident_id}")

    def get_lock_info(self, incident_id: str, lock_name: str) -> dict:
        """Run demisto-lock-info and return the result."""
        return self.run_command(incident_id, f"!demisto-lock-info name={lock_name}")

    def release_all_locks(self, incident_id: str) -> None:
        """Clean up — release all locks."""
        self.run_command(incident_id, "!demisto-lock-release-all")


def create_incident_and_trigger(client: XSOARClient, index: int, playbook: str, lock_name: str) -> str:
    """Create one incident and immediately trigger the lock-get + release sequence."""
    incident_name = f"LockStressTest-{index}-{int(time.time())}"
    print(f"  [{index}] Creating incident: {incident_name}")
    incident_id = client.create_incident(incident_name, playbook)
    print(f"  [{index}] Incident created: #{incident_id}")

    # Immediately run lock-get (no sleep — maximise concurrency)
    client.run_command(incident_id, f"!demisto-lock-get name={lock_name} timeout=60 polling_interval=5")
    print(f"  [{index}] lock-get done for incident #{incident_id}")

    # Immediately release
    client.run_command(incident_id, f"!demisto-lock-release name={lock_name}")
    print(f"  [{index}] lock-release done for incident #{incident_id}")

    return incident_id


def main() -> None:
    args = parse_args()
    client = XSOARClient(args.url, args.api_key, verify_ssl=not args.insecure)

    print(f"\n{'='*60}")
    print(f"Demisto Lock Stress Test — XSUP-67021")
    print(f"{'='*60}")
    print(f"Target:    {args.url}")
    print(f"Incidents: {args.incidents}")
    print(f"Lock name: {args.lock_name}")
    print(f"Playbook:  {args.playbook}")
    print(f"{'='*60}\n")

    # First, clean up any leftover locks from previous runs
    print("[*] Cleaning up any existing locks...")
    try:
        seed_id = client.create_incident("LockStressTest-cleanup", args.playbook)
        client.release_all_locks(seed_id)
        print(f"    Cleanup done (incident #{seed_id})")
    except Exception as e:
        print(f"    Cleanup warning: {e}")

    print(f"\n[*] Launching {args.incidents} concurrent lock-get + lock-release operations...\n")
    start_time = time.time()
    incident_ids: list[str] = []

    # Run all incidents concurrently — this is what creates the race condition
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.incidents) as executor:
        futures = [
            executor.submit(create_incident_and_trigger, client, i, args.playbook, args.lock_name)
            for i in range(args.incidents)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                incident_ids.append(future.result())
            except Exception as e:
                print(f"  [ERROR] {e}")

    elapsed = time.time() - start_time
    print(f"\n[*] All {len(incident_ids)} operations completed in {elapsed:.1f}s")

    # Check for stuck locks
    print(f"\n[*] Checking for stuck locks on '{args.lock_name}'...")
    if not incident_ids:
        print("    No incidents created — cannot check.")
        sys.exit(1)

    check_incident = incident_ids[0]
    try:
        result = client.get_lock_info(check_incident, args.lock_name)
        entries = result.get("entries", [])
        lock_found = False
        for entry in entries:
            contents = entry.get("contents", "")
            if isinstance(contents, list) and len(contents) > 0:
                lock_found = True
                break
            if isinstance(contents, str) and "Locked" in contents:
                lock_found = True
                break

        print(f"\n{'='*60}")
        if lock_found:
            print(f"  ❌ BUG REPRODUCED: Lock '{args.lock_name}' is STILL LOCKED after all releases!")
            print(f"     This confirms the lost-update race condition (XSUP-67021).")
            print(f"     Raw lock-info response: {json.dumps(result, indent=2)[:500]}")
        else:
            print(f"  ✅ PASS: Lock '{args.lock_name}' is fully released — no stuck locks.")
            print(f"     Either the fix is applied, or the race window was not hit this run.")
            print(f"     Try increasing --incidents to raise the probability of hitting the race.")
        print(f"{'='*60}\n")

    except Exception as e:
        print(f"  [ERROR] Could not check lock info: {e}")

    # Final cleanup
    print("[*] Final cleanup — releasing all locks...")
    try:
        client.release_all_locks(check_incident)
        print("    Done.\n")
    except Exception as e:
        print(f"    Cleanup error: {e}\n")


if __name__ == "__main__":
    main()
