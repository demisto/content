import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import requests
import json
from typing import List, Dict, Any
import dateparser

# -----------------------------
# Predefined sharing groups map
# -----------------------------
SHARING_GROUPS_MAP = {
    "tnt": 8,
    "raolf": 7,
    "mti": 4,
    "dga": 9,
    "tor": 13,
    "vpn": 14,
    "tnt_ransomware": 17,
    "proxy": 19
}

# -----------------------
# Integration config parameters
# -----------------------
PARAMS = demisto.params()
BASE_URL: str = PARAMS.get('url', '').rstrip('/')
API_KEY: str = PARAMS.get("credentials", {}).get("password")
INSECURE: bool = PARAMS.get('insecure', False)  # checkbox in integration config
TIMEOUT: int = int(PARAMS.get('timeout', 120))

HEADERS = {
    "Authorization": API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

ATTRIBUTES_ENDPOINT = "/attributes/restSearch"


# -----------------------
# Helper functions
# -----------------------
def _extract_minimal_attributes_to_display(ioc_results: List) -> List:
    temp_list_to_return = []
    if not ioc_results:
        return []

    for result in ioc_results:
        minimal_object = {
            "first_seen": result.get("first_seen", "None"),
            "last_seen": result.get("last_seen", "None"),
            "value": result.get("value", "None"),
            "Event": result.get("Event", "None"),
            "type": result.get("type", "None"),
            "id": result.get("id", "None"),
            "uuid": result.get("uuid", "None"),
            "category": result.get("category", "None"),
            "sharing_group_id": result.get("sharing_group_id", "None"),
            "comment": result.get("comment", "None"),
            "deleted": result.get("deleted", False)
        }

        temp_list_to_return.append(minimal_object)

    return temp_list_to_return


def _parse_sharing_groups(arg: str) -> List[int]:
    """
    Accepts a comma-separated list of sharing group *names only*, for example:
    "tnt,raolf,tor"
    "TNT_RANSOMWARE, DGA"

    Returns:
    List of integer sharing group IDs from SHARING_GROUPS_MAP.

    Raises:
    DemistoException if unknown names are provided.
    """

    if not arg:
        return []

    # Split into tokens
    tokens = [t.strip() for t in arg.split(",") if t.strip()]

    ids: List[int] = []
    invalid: List[str] = []

    for t in tokens:
        # Normalize variations: lowercase + underscores for matching
        key = t.lower()

        if key in SHARING_GROUPS_MAP:
            ids.append(SHARING_GROUPS_MAP[key])
        else:
            invalid.append(t)

    # If user provided anything unknown, fail hard (better UX)
    if invalid:
        raise DemistoException(
            f"Invalid sharing group name(s): {', '.join(invalid)}. "
            f"Allowed values: {', '.join(sorted(SHARING_GROUPS_MAP.keys()))}"
        )

    return ids


def _safe_post(url: str, headers: Dict[str, str], payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute POST to MISP and return parsed JSON or raise a useful error.
    """
    try:
        resp = requests.post(url, headers=headers, json=payload, verify=not INSECURE, timeout=TIMEOUT)
    except requests.exceptions.RequestException as e:
        demisto.error(f"RequestException when calling MISP: {str(e)}")
        raise DemistoException(f"Failed to call MISP: {str(e)}")

    if resp is None:
        raise DemistoException("No response received from MISP API.")

    status = resp.status_code
    text = resp.text or ""

    if status != 200:
        demisto.error(f"MISP returned status {status}: {text}")
        raise DemistoException(f"MISP API returned status {status}: {text}")

    try:
        return resp.json()
    except ValueError:
        demisto.error(f"Failed to parse JSON from MISP response. Raw response: {text}")
        raise DemistoException("MISP returned an invalid JSON response. See server logs for details.")


# -----------------------
# Command implementation
# -----------------------
def ncfta_get_iocs_command(args: Dict[str, Any]) -> CommandResults:
    """
    ncfta-get-iocs command:
    - sharing_groups: comma-separated string of sharing group IDs (e.g. "4,6,7")
    - timestamp: e.g. "7d", "24h", "6h" (default 7d)
    - limit: limit number of IOC's in the response. Default: 100
    """
    sharing_groups_arg = args.get("sharing_groups", [])
    timestamp = args.get("timestamp", "7d")
    limit = int(args.get("limit", "100"))

    sharing_group_ids = _parse_sharing_groups(sharing_groups_arg)

    payload = {
        "timestamp": timestamp,
        "limit": limit,
        "returnFormat": "json"
    }

    if sharing_group_ids:
        payload["sharinggroup"] = sharing_group_ids

    # Build request URL
    if not BASE_URL:
        raise DemistoException("Integration parameter 'url' is not configured.")
    url = f"{BASE_URL}{ATTRIBUTES_ENDPOINT}"

    # Perform the request
    raw_response_json = _safe_post(url, HEADERS, payload)
    response_json = raw_response_json.get("response", {}).get("Attribute", [])
    response_json = _extract_minimal_attributes_to_display(response_json)
    output_results = {
        "count": len(response_json),
        "results": response_json
    }

    return CommandResults(
        outputs_prefix="NCFTA.Attributes",
        outputs_key_field="",
        outputs=output_results,
        readable_output=f"Fetched {len(response_json)} attributes"
    )


""" MAIN FUNCTION """


def main():
    try:
        command = demisto.command()
        demisto.info(f"Command being called: {command}")
        if command == "test-module":
            return_results("ok")
        elif command == "ncfta-get-iocs":
            return_results(ncfta_get_iocs_command(demisto.args()))
        else:
            return_error(f"Unknown command called: {command}")
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute NCFTA integration. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
