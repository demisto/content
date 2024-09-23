import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import traceback
from collections import defaultdict
from ipaddress import ip_address
from typing import DefaultDict, Tuple
from requests import Response

import urllib3


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VALID_PEER_ROLES = ["any", "client", "server"]

VALID_PROTOCOLS = ["any", "AAA", "ActiveMQ", "AJP", "amf", "CIFS", "DB", "DHCP", "DICOM", "DNS", "FIX", "FTP", "HL7",
                   "HTTP", "IBMMQ", "ICA", "IKE/ISAKMP", "IMAP", "IPFIX", "IPsec NAT-T", "IRC", "iSCSI", "Kerberos",
                   "L2TP", "LDAP", "lync-compress", "memcache", "Modbus", "MongoDB", "MSMQ", "MSN", "MSRPC", "NetFlow",
                   "NFS", "NTP", "OpenVPN", "PCoIP", "Perforce", "POP3", "RDP", "Redis", "RFB", "RTCP", "RTP", "sFlow",
                   "SIP", "SMPP", "SMTP", "SNMP", "SSH", "SSL", "Syslog", "TCP", "telnet", "UDP", "WebSocket"]

VALID_DEVICE_ROLES = ["db_server", "dhcp_server", "dns_server", "file_server", "firewall", "gateway", "http_server",
                      "domain_controller", "web_proxy", "load_balancer", "pc", "medical_device", "mobile_device",
                      "printer", "scanner", "custom", "voip_phone", "other"]

VALID_DEVICE_SOFTWARES = ["android", "apple_ios", "arista_eos", "cisco_ios", "cisco_nx-os", "chrome_os", "linux",
                          "mac_os", "windows", "windows_server", "windows_server_2008", "windows_server_2008_r2",
                          "windows_server_2012", "windows_server_2012_r2", "windows_server_2016", "windows_vista",
                          "windows_7", "windows_8", "windows_8.1", "windows_10"]

VALID_DEVICE_VENDORS = ["alcatel-lucent", "apple", "arista", "asus", "brother", "canon", "cisco", "cisco-linksys",
                        "citrix", "dell", "dellemc", "d-link", "emc", "f5", "google", "hp", "htc", "huawei", "ibm",
                        "juniper", "kyocera", "microsoft", "netapp", "netgear", "nokia", "nortel", "oracle", "paloalto",
                        "samsung", "3com", "toshiba", "virtualbox", "vmware", "zte"]

VALID_DEVICE_ACTIVITIES = ["aaa_client", "aaa_server", "ajp_client", "ajp_server", "amf_client", "amf_server",
                           "cifs_client", "cifs_server", "db_client", "db_server", "dhcp_client", "dhcp_server",
                           "dicom_client", "dicom_server", "dns_client", "dns_server", "fix_client", "fix_server",
                           "ftp_client", "ftp_server", "hl7_client", "hl7_server", "http_client", "http_server",
                           "ibmmq_client", "ibmmq_server", "ica_client", "ica_server", "icmp", "iscsi_client",
                           "iscsi_server", "kerberos_client", "kerberos_server", "ldap_client", "ldap_server",
                           "llmnr_client", "llmnr_server", "memcache_client", "memcache_server", "modbus_client",
                           "modbus_server", "mongo_client", "mongo_server", "msmq", "nbns_client", "nbns_server",
                           "nfs_client", "nfs_server", "pcoip_client", "pcoip_server", "pop3_client", "pop3_server",
                           "rdp_client", "rdp_server", "redis_client", "redis_server", "rfb_client", "rfb_server",
                           "rpc_client", "rpc_server", "rtcp", "rtp", "scanner", "sip_client", "sip_server",
                           "smpp_client", "smpp_server", "smtp_client", "smtp_server", "ssh_client", "ssh_server",
                           "ssl_client", "ssl_server", "tcp", "telnet_client", "telnet_server", "udp",
                           "websocket_client",
                           "websocket_server", "wsman_client", "wsman_server"]

VALID_DEVICE_OPERATORS = [">", "<", "<=", ">=", "=", "!=", "startswith", "exists", "not_exists", "~", "!~"]

VALID_DEVICE_MATCH_TYPES = ["and", "or", "not"]

VALID_TIME_INTERVALS = ["30 minutes", "6 hours", "1 day", "1 week"]

VALID_FILE_FORMATS = ["pcap", "keylog_txt", "zip"]

VALID_INCIDENT_STATUS = ["0", "1", "2", "3"]

TICKET_STATUS_MAP = {
    "0": "new",  # pending
    "1": "in_progress",  # active
    "2": "closed",  # done
    "3": "acknowledged"  # archived
}

TICKET_SEVERITY = {
    "0-39": 1,  # low
    "40-69": 2,  # medium
    "70-89": 3,  # high
    "90-100": 4  # critical
}

VALID_ALERT_RULE_REFIRE_INTERVALS = ["300", "600", "900", "1800", "3600", "7200", "14400"]

VALID_ALERT_RULE_TYPE = ["threshold", "detection"]

VALID_ALERT_RULE_SEVERITY = ["0", "1", "2", "3", "4", "5", "6", "7"]

VALID_ALERT_RULE_INTERVAL_LENGTH = ["30", "60", "120", "300", "600", "900", "1200", "1800"]

SORT_DIRECTION = ["asc", "desc"]

VALID_ALERT_RULE_OPERATOR = ["==", ">", "<", ">=", "<="]

VALID_ALERT_RULE_UNITS = ["none", "period", "1 sec", "1 min", "1 hr"]

VALID_ALERT_RULE_OBJECT_TYPES = ["application", "device"]

VALID_CYCLES = ["auto", "1sec", "30sec", "5min", "1hr", "24hr"]

VALID_OBJECT_TYPES = ["device", "network", "application", "vlan", "device_group", "system"]

VALID_METRICS_KEYS = ["cycle", "from", "metric_category", "metric_specs", "object_ids", "object_type", "until"]

VALID_DETECTION_KEYS = ["filter", "limit", "offset", "from", "until", "sort", "mod_time"]

VALID_FILTER_KEYS = ["assignee", "categories", "category", "resolution", "risk_score_min", "status", "ticket_id", "types"]

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

DEFAULT_FETCH_TYPE = 'ExtraHop Detections'

FIRST_FETCH = "3 days"

MAX_FETCH = 200

EXTRAHOP_MARKDOWN_REGEX = r"(\[[^\]]+\]\(\#\/[^\)]+\))+"

""" CLIENT CLASS """


class ExtraHopClient(BaseClient):

    def __init__(self, base_url: str, api_key: str, client_id: str, client_secret: str, verify: bool, use_proxy: bool,
                 ok_codes: tuple, on_cloud: bool) -> None:
        """
       Prepare constructor for Client class.

       Calls the constructor of BaseClient class and updates the header with the authentication token.

       Args:
           base_url: The url of ExtraHop instance.
           api_key: The api key to use in header.
           client_id: The Client ID to use for authentication.
           client_secret: The Client Secret to use for authentication.
           verify: True if verify SSL certificate is checked in integration configuration, False otherwise.
           use_proxy: True if the proxy server needs to be used, False otherwise.
       """

        super().__init__(base_url=base_url, verify=verify, ok_codes=ok_codes, proxy=use_proxy)

        # Setting up access token in headers.
        if on_cloud:
            self._headers: Dict[str, Any] = {
                "Authorization": f"Bearer {self.get_access_token(client_id=client_id, client_secret=client_secret)}",
                "ExtraHop-Integration": "XSOAR-6.5.0-ExtraHop-2.0.0"
            }
        else:
            self._headers = {
                "Accept": "application/json",
                "Authorization": f"ExtraHop apikey={api_key}",
                "ExtraHop-Integration": "XSOAR-6.5.0-ExtraHop-2.0.0"
            }

    def get_access_token(self, client_id: str, client_secret: str) -> str:
        """Return the token stored in integration context.

        If the token has expired or is not present in the integration context
        (in the first case), it calls the Authentication function, which
        generates a new token and stores it in the integration context.

        Args:
            client_id: The Client ID to use for authentication.
            client_secret: The Client Secret to use for authentication.

        Returns:
            str: Authentication token stored in integration context.
        """
        integration_context = get_integration_context()
        token = integration_context.get("access_token")
        valid_until = integration_context.get("valid_until")
        time_now = int(time.time())

        # If token exists and is valid, then return it.
        if (token and valid_until) and (time_now < valid_until):
            demisto.info("Extrahop token returned from integration context.")
            return token

        # Otherwise, generate a new token and store it.
        token, expires_in = self.authenticate(client_id=client_id, client_secret=client_secret)
        integration_context = {
            "access_token": token,
            "valid_until": time_now + expires_in,  # Token expiration time - 30 mins
        }
        set_integration_context(integration_context)

        return token

    def authenticate(self, client_id: str, client_secret: str) -> Tuple[str, int]:
        """
        Get the access token from the ExtraHop API.

        Args:
            client_id: The Client ID to use for authentication.
            client_secret: The Client Secret to use for authentication.

        Returns:
            tuple[str,int]: The token and its expiration time in seconds received from the API.
        """
        demisto.info("Generating new authentication token.")

        req_headers = {
            "cache-control": "no-cache",
            "content-type": "application/x-www-form-urlencoded",
        }
        req_body = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        response = self._http_request(
            method="POST",
            url_suffix="/oauth2/token",
            data=req_body,
            headers=req_headers
        )
        token = response.get("access_token")
        expires_in = response.get("expires_in")

        return token, expires_in

    def test_connection(self):
        """Test the authentication."""
        return self._http_request(method="GET", url_suffix="/api/v1/extrahop",
                                  error_handler=authentication_error_handler)

    def get_extrahop_version(self):
        """Retrieve the ExtraHop version."""
        return self._http_request(method="GET", url_suffix="/api/v1/extrahop/version")

    def get_appliance_uuids(self):
        """Retrieve the appliance IDs.

        Returns:
            Response from the API.
        """
        networks = self._http_request("GET", url_suffix="/api/v1/networks")
        uuid_lookup = {}
        for network in networks:
            uuid_lookup[network["node_id"]] = network.get("appliance_uuid")
        return uuid_lookup

    def get_device_by_id(self, device_id: str, ok_codes: Tuple = None):
        """Retrieve the device from the Reveal(X).

        Args:
            device_id: Unique ID of the device to be retrieved.
            ok_codes: The status code to not raise error for while fetching detections.

        Returns:
            Response from the API.
        """
        return self._http_request("GET", url_suffix=f"/api/v1/devices/{device_id}", ok_codes=ok_codes)

    def device_search(self, name: Optional[str], ip: Optional[str], mac: Optional[str], role: Optional[str],
                      software: Optional[str], vendor: Optional[str], tag: Optional[str], discover_time: Optional[str],
                      vlan: Optional[str], activity: Optional[str], operator: Optional[str], match_type: Optional[str],
                      active_from: Optional[str], active_until: Optional[str], limit: Optional[int],
                      l3_only: Optional[bool]):
        """Searches for a device from the Reveal(X).

        Args:
            name: Name of the device.
            ip: IP address of the device.
            mac: Mac address of the device.
            role: Role of the device.
            software: Software used in the device.
            vendor: Vendor of the device.
            tag: Tags of the device.
            discover_time: The time device was discovered.
            vlan: vlan of the device.
            activity: activity information of the device.
            operator: Operator of the device.
            match_type: Match type of the device.
            active_from: Date the device is active from.
            active_until: Date the device was last active.
            limit: Limit of the response
            l3_only: Whether the device is a layer 3 device.

        Returns:
            Response from the API.
        """
        fields = {
            "name": name,
            "ipaddr": ip,
            "macaddr": mac,
            "role": role,
            "software": software,
            "vendor": vendor,
            "tag": tag,
            "discover_time": discover_time,
            "vlan": vlan,
            "activity": activity
        }

        data: Dict[str, Any] = {}
        if active_from:
            data["active_from"] = int(active_from)
        if active_until:
            data["active_until"] = int(active_until)
        if limit:
            data["limit"] = int(limit)
        if any([val is not None for val in fields.values()]):
            data["filter"] = {
                "operator": match_type,
                "rules": []
            }
            rules_list = data["filter"]["rules"]

            if l3_only:
                rules_list.append(
                    {
                        "field": "ipaddr",
                        "operator": "exists"
                    }
                )
                if match_type != "and":
                    data["filter"]["operator"] = "and"
                    rules_list.append(
                        {
                            "operator": match_type,
                            "rules": []
                        }
                    )
                    rules_list = data["filter"]["rules"][1]["rules"]

            for field in fields.items():
                if field[1]:
                    search_filter = {
                        "field": field[0],
                        "operator": operator,
                        "operand": field[1]
                    }
                    rules_list.append(search_filter)
        return self._http_request("POST", url_suffix="/api/v1/devices/search", json_data=data)

    def get_watchlist(self):
        """Retrieve all the devices on the watchlist in Reveal(X).

        Returns:
            Response from the API.
        """
        return self._http_request("GET", url_suffix="/api/v1/watchlist/devices")

    def edit_watchlist(self, body: Dict):
        """Retrieve all devices that are in the watchlist.

        Args:
            body: Json payload to pass with the API.
        """

        self._http_request("POST", url_suffix="/api/v1/watchlist/devices", json_data=body, resp_type="response")

    def get_peers(self, body: Dict):
        """Retrieve the peers of a device from Reveal(X).

        Returns:
            Response from the API.
        """
        return self._http_request("POST", url_suffix="/api/v1/activitymaps/query", json_data=body)

    def get_alert_rules(self):
        """Retrieve the alert rules from Reveal(X).

        Returns:
            Response from the API.
        """
        return self._http_request("GET", url_suffix="/api/v1/alerts")

    def patch_detections(self, detection_id: str, body: Dict):
        """Patch a detection with provided fields.

        Args:
            detection_id: The unique identifier for the detection.
            body: Json payload to pass with the API.
        Returns:
            Response from the API.
        """
        return self._http_request("PATCH", url_suffix=f"/api/v1/detections/{detection_id}", json_data=body,
                                  resp_type="response")

    def packets_search(self, output: Optional[str], limit_bytes: Optional[str], limit_search_duration: Optional[str],
                       query_from: Optional[str], query_until: Optional[str], bpf: Optional[str], ip1: Optional[str],
                       port1: Optional[str], ip2: Optional[str], port2: Optional[str]):
        """Retrieve the specific packets from Reveal(X).

        Args:
            output: The output format
            limit_bytes: The maximum number of bytes to return.
            limit_search_duration: The maximum amount of time to run the packet search.
            query_from: The beginning timestamp of the time range the search will include.
            query_until: The ending timestamp of the time range the search will include.
            bpf: The Berkeley Packet Filter (BPF) syntax for the packet search.
            ip1: Returns packets sent to or received by the specified IP address.
            port1: Returns packets sent from or received on the specified port.
            ip2: Returns packets sent to or received by the specified IP address.
            port2: Returns packets sent from or received on the specified port.

        Returns:
            Response from the API.
        """
        body = {
            "output": output,
            "limit_bytes": limit_bytes,
            "limit_search_duration": limit_search_duration,
            "always_return_body": False,
            "from": query_from,
            "until": query_until,
            "bpf": bpf,
            "ip1": ip1,
            "port1": port1,
            "ip2": ip2,
            "port2": port2
        }

        return self._http_request("GET", url_suffix="/api/v1/packets/search", json_data=body, resp_type="response")

    def get_all_tags(self):
        """Retrieve all available tags from Reveal(X).

        Returns:
            Response from the API.
        """
        return self._http_request("GET", url_suffix="/api/v1/tags")

    def create_new_tag(self, data: Dict):
        """Create a new tag.

        Returns:
            Response from the API.
        """
        return self._http_request("POST", url_suffix="/api/v1/tags", json_data=data, resp_type="response")

    def tag_untag_devices(self, tag_id: str, data: Dict):
        """Tag and untag devices for the given tag id.

        Returns:
            Response from the API.
        """
        return self._http_request("POST", url_suffix=f"/api/v1/tags/{tag_id}/devices", json_data=data,
                                  resp_type="response")

    def create_alert_rule(self, body: Dict):
        """Create a new alert rule with specified value.

        Args:
            body: Request body of alert rule.

        Returns:
            Response from the API.
        """
        return self._http_request("POST", url_suffix="/api/v1/alerts", json_data=body, empty_valid_codes=[201],
                                  return_empty_response=True)

    def update_alert_rule(self, alert_id, body):
        """Update alert rule with specified value.

        Args:
            alert_id: The unique identifier of the alert.
            body: Json payload to pass with the API.

        Returns:
            Response from the API.
        """
        return self._http_request("PATCH", url_suffix=f"/api/v1/alerts/{alert_id}", json_data=body,
                                  return_empty_response=True)

    def metrics_list(self, body: Dict):
        """Retrieves metric information collected about every object from the Reveal(X).
        Args:
            body: Request body of metric list.

        Returns:
            Response from the API.
        """
        return self._http_request("POST", url_suffix="/api/v1/metrics", json_data=body)

    def detections_list(self, body):
        """Retrieve the detections from Reveal(X).

        Returns:
            Response from the API.
        """
        return self._http_request("POST", url_suffix="/api/v1/detections/search", json_data=body)

    def get_detections_by_id(self, detection_id):
        """Retrieve the detections from Reveal(X).

        Returns:
            Response from the API.
        """
        return self._http_request("GET", url_suffix=f"/api/v1/detections/{detection_id}")

    def get_query_records(self, body: Dict):
        """Get query records for specified filter.
        Args:
            body: JSON payload to pass with the API.
        """
        return self._http_request("POST", url_suffix="/api/v1/records/search", json_data=body)

    def get_next_page_records(self, cursor):
        """Get next page records from specified cursor value.
        Args:
            cursor: Cursor value to get records.
        """
        body = {
            "cursor": cursor
        }
        params = {
            "context_ttl": 30000
        }
        return self._http_request("POST", url_suffix="/api/v1/records/cursor", json_data=body, params=params)


""" EXCEPTION CLASS """


class InvalidValueError(Exception):
    """Custom exception class for invalid values."""

    def __init__(self, arg_name="", arg_value="", arg_list=[], message=""):
        if not message:
            message = f"{arg_value} is an invalid value for {arg_name}. Possible values are: {arg_list}"
        super().__init__(message)


""" HELPER FUNCTIONS """


def modify_description(base_url, description):
    """Modify descriptions of the detections list.

    Args:
        base_url: Base URL of the instance.
        description: Detection description.

    Returns:
        Updated description.
    """
    new_link = f"{base_url}/extrahop/#"

    markdown_data = re.findall(EXTRAHOP_MARKDOWN_REGEX, description)

    for markdown in markdown_data:
        # Replacing the '#' to the extrahop platform url
        if "/extrahop/#" in markdown:
            new_markdown = markdown.replace("#/extrahop", base_url)
        else:
            new_markdown = markdown.replace("#", new_link)
        description = description.replace(markdown, new_markdown)
    return description


def get_extrahop_server_version(client: ExtraHopClient):
    """Retrieve and parse the extrahop server version.

    Args:
        client: ExtraHop client to be used.

    Returns:
        The parsed version of the current extrahop server.

    """
    version = client.get_extrahop_version().get("version")
    temp = version.split(".")
    version = ".".join(temp[:3])
    return version


def remove_empty_elements_from_response(data: Union[Dict, List, None, str]) -> Union[Dict, List, str, None]:
    """Recursively remove empty lists, empty dicts, or None elements from a dictionary.

    Args:
        data: Data from which empty elements are to be removes

    Returns:
        Data with no empty fields.
    """

    def empty(x):
        return x is None or x == {} or x == [] or x == ""

    if not isinstance(data, (dict, list)):
        return data
    elif isinstance(data, list):
        return [v for v in (remove_empty_elements_from_response(v) for v in data) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements_from_response(v)) for k, v in data.items()) if not empty(v)}


def authentication_error_handler(res: Response) -> None:
    """Handle 400, 401, 403, 404, 5XX error.

    Args:
        res: The response object obtained from API.

    Raises: ValueError if the status code is 401 or 400.
    """
    if res.status_code == 400:
        raise ValueError("Error code 400: Attempt to bad request.")

    elif res.status_code == 401:
        raise ValueError("Error code 401: Invalid credentials provided.")

    elif res.status_code == 403:
        raise ValueError("Error code 403: Attempt to access forbidden resource.")

    elif res.status_code == 404:
        raise ValueError("Error code 404: The requested resource cannot be found.")

    else:
        raise ValueError("Internal server error.")


def trim_spaces_from_args(args: Dict) -> Dict:
    """Trim spaces from values of the args dict.

    Args:
        args: Dict to trim spaces from.

    Returns:
        Arguments after trim spaces.
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def remove_api_from_base_url(url: str) -> str:
    """Prepare URL from base URL required for human-readable.

    Args:
        url: Base URL of the cloud instance.

    Returns:
        ExtraHop cloud instance URL.
    """
    url = url.split(".")
    url.pop(1)
    return ".".join(url)


def validate_peers_get_arguments(peer_role: Optional[Any], protocol: Optional[Any]) -> None:
    """Validate arguments for peers-get command.

    Args:
        peer_role: The role of the peer device in relation to the origin device.
        protocol: The protocol over which the source device is communicating.
    """

    if peer_role and peer_role not in VALID_PEER_ROLES:
        raise InvalidValueError("peer_role", peer_role, VALID_PEER_ROLES)

    if protocol and protocol not in VALID_PROTOCOLS:
        raise InvalidValueError("protocol", protocol, VALID_PROTOCOLS)


def validate_device_search_arguments(role: Optional[str], software, vendor: Optional[str], activity: Optional[str],
                                     operator: Optional[str], match_type: Optional[str],
                                     l3_only: Optional[bool]) -> None:
    """Validate arguments for peers-get command.

    Args:
        role: The role of the device.
        software: The OS of the device.
        vendor: The vendor of the device, based on MAC address via OUI lookup.
        activity: The activity of the device.
        operator: The compare method applied when matching the fields against their values
        match_type: The match operator to use when chaining the search fields together.
        l3_only: Only returns layer 3 devices by filtering out any layer 2 parent devices.
    """
    if role and role not in VALID_DEVICE_ROLES:
        raise InvalidValueError("role", role, VALID_DEVICE_ROLES)

    if software and software not in VALID_DEVICE_SOFTWARES:
        raise InvalidValueError("software", software, VALID_DEVICE_SOFTWARES)

    if vendor and vendor not in VALID_DEVICE_VENDORS:
        raise InvalidValueError("vendor", vendor, VALID_DEVICE_VENDORS)

    if activity and activity not in VALID_DEVICE_ACTIVITIES:
        raise InvalidValueError("activity", activity, VALID_DEVICE_ACTIVITIES)

    if operator and operator not in VALID_DEVICE_OPERATORS:
        raise InvalidValueError("operator", operator, VALID_DEVICE_OPERATORS)

    if match_type and match_type not in VALID_DEVICE_MATCH_TYPES:
        raise InvalidValueError("match_type", match_type, VALID_DEVICE_MATCH_TYPES)

    if l3_only:
        argToBoolean(l3_only)


def validate_activity_map_get_arguments(ip_or_id: Optional[str], time_interval: str, from_time: Optional[str],
                                        until_time: Optional[str], peer_role: str, protocol: str) -> None:
    """Validate arguments for peers-get command.

    Args:
        ip_or_id: IP address or unique ID of the device.
        time_interval: Time interval of the live activity map.
        from_time: The beginning timestamp of a fixed time range.
        until_time: The ending timestamp of a fixed time range.
        peer_role: The role of the peer devices in relation to the source device.
        protocol: The protocol over which the source device is communicating.
    """
    if not ip_or_id.isdigit():  # type: ignore
        ip_address(ip_or_id)  # type: ignore

    if time_interval and time_interval not in VALID_TIME_INTERVALS:
        raise InvalidValueError("time_interval", time_interval, VALID_TIME_INTERVALS)

    if from_time:
        arg_to_number(from_time, "from_time")

    if until_time:
        arg_to_number(until_time, "until_time")

    if peer_role and peer_role not in VALID_PEER_ROLES:
        raise InvalidValueError("peer_role", peer_role, VALID_PEER_ROLES)

    if protocol and protocol not in VALID_PROTOCOLS:
        raise InvalidValueError("protocol", protocol, VALID_PROTOCOLS)


def validate_ticket_track_arguments(incident_status: str):
    """Validate arguments for ticket-track command.

    Args:
        incident_status: The status of the incident.
    """
    if incident_status and incident_status not in VALID_INCIDENT_STATUS:
        raise InvalidValueError("incident_status", incident_status, VALID_INCIDENT_STATUS)


def validate_packets_search_arguments(output: str) -> None:
    """Validate arguments for peers-get command.

    Args:
        output: The output format.
    """
    if output and output not in VALID_FILE_FORMATS:
        raise InvalidValueError("output", output, VALID_FILE_FORMATS)


def validate_add_and_remove_arguments(add: str, remove: str) -> None:
    """Validate add and remove arguments for command.

    Args:
        add: The list of IP or device ID to add tag.
        remove: The list of IP or device ID to remove tag.
    """
    if not add and not remove:
        raise DemistoException("No device id provided to add or remove arguments.")


def validate_create_or_update_alert_rule_arguments(refire_interval: Optional[str], severity: Optional[str],
                                                   alert_type: Optional[str]) -> None:
    """Validate arguments for extrahop-alert-rule-create and extrahop-alert-rule-update commands.

    Args:
        refire_interval: The time interval in which alert conditions are monitored, expressed in seconds.
        severity: The severity level of the alert, which is displayed in the Alert History,
                    email notifications, and SNMP traps.
        alert_type: The type of alert.
    """
    if refire_interval and refire_interval not in VALID_ALERT_RULE_REFIRE_INTERVALS:
        raise InvalidValueError("refire_interval", refire_interval, VALID_ALERT_RULE_REFIRE_INTERVALS)
    if severity and severity not in VALID_ALERT_RULE_SEVERITY:
        raise InvalidValueError("severity", severity, VALID_ALERT_RULE_SEVERITY)
    if alert_type and alert_type not in VALID_ALERT_RULE_TYPE:
        raise InvalidValueError("type", alert_type, VALID_ALERT_RULE_TYPE)


def validate_threshold_alert_rule_arguments(interval_length: Optional[str], operator: Optional[str],
                                            units: Optional[str]) -> None:
    """Validate arguments for extrahop-alert-rule-create and extrahop-alert-rule-update commands for alert_type:
    threshold.

    Args:
        interval_length: The length of the alert interval, expressed in seconds.
        operator: The logical operator applied when comparing the value of the operand field to alert conditions
        units: The interval in which to evaluate the alert condition.
    """
    if interval_length and interval_length not in VALID_ALERT_RULE_INTERVAL_LENGTH:
        raise InvalidValueError("interval_length", interval_length, VALID_ALERT_RULE_INTERVAL_LENGTH)
    if operator and operator not in VALID_ALERT_RULE_OPERATOR:
        raise InvalidValueError("operator", operator, VALID_ALERT_RULE_OPERATOR)
    if units and units not in VALID_ALERT_RULE_UNITS:
        raise InvalidValueError("units", units, VALID_ALERT_RULE_UNITS)


def validate_metrics_list_arguments(body: Dict) -> None:
    """Validate arguments for metrics-list command.

    Args:
        body: Payload of the API request.
    """
    keys = body.keys()

    for key in keys:
        if key not in VALID_METRICS_KEYS:
            raise InvalidValueError("keys", key, VALID_METRICS_KEYS)

    if body.get("cycle") not in VALID_CYCLES:
        raise InvalidValueError("cycle", body["cycle"], VALID_CYCLES)

    if body.get("object_type") not in VALID_OBJECT_TYPES:
        raise InvalidValueError("object_type", body["object_type"], VALID_OBJECT_TYPES)


def validate_detections_list_arguments(body: Dict) -> None:
    """Validate arguments for list-detections command.

    Args:
        body: The payload of the API request.

    Raises:
        DemistoException if invalid input given for an argument.
    """
    body = trim_spaces_from_args(body)
    for key in body.keys():
        if key not in VALID_DETECTION_KEYS:
            raise InvalidValueError("key", key, VALID_DETECTION_KEYS)

    if body.get("filter"):
        for key in body["filter"].keys():
            if key not in VALID_FILTER_KEYS:
                raise InvalidValueError("key", key, VALID_FILTER_KEYS)

    if body.get("from") and body.get("until") and body["from"] > body["until"]:
        raise DemistoException("Input for \"from\" should always be less than that of \"until\".")

    if isinstance(body.get("limit"), int):
        if body["limit"] <= 0:
            raise DemistoException("Invalid input for field limit. It should have numeric value greater than zero.")

        body["limit"] = min(body["limit"], 200)
    else:
        body["limit"] = 200

    if isinstance(body.get("offset"), int):
        if body["offset"] < 0:
            raise DemistoException(
                "Invalid input for field offset. It should have numeric value greater than or equal to zero.")
    else:
        body["offset"] = 0


def add_default_category_for_filter_of_detection_list(_filter: Dict) -> None:
    """Set a default category for filter argument.

    Args:
        _filter: Filter argument for detection list command.
    """
    if "category" not in _filter:
        if "categories" not in _filter:
            _filter["categories"] = ["sec.attack"]
        elif isinstance(_filter.get("categories"), list):
            valid_categories = []
            for category in _filter.get("categories", []):
                if isinstance(category, str):
                    category = category.strip()
                    if category:
                        valid_categories.append(category)
            _filter["categories"] = valid_categories if valid_categories else ["sec.attack"]


def format_protocol_stack(protocol_list: List) -> str:
    """Formats the protocol stack.

    Args:
        protocol_list: List of protocols.

    Returns:
        String of formatted protocols.
    """
    if len(protocol_list) > 1:
        protos = protocol_list[1:]
    else:
        protos = protocol_list

    return ":".join(protos)


def sort_protocols(protos_by_weight: Dict) -> List:
    """Sort protocols by weight.

    Args:
        protos_by_weight: Weighted dictionary of protocols.

    Returns:
        Sorted List fo protocols.
    """
    sorted_protos = sorted(protos_by_weight.items(), key=lambda x: x[1], reverse=True)
    return [proto_tuple[0] for proto_tuple in sorted_protos]


def get_device_by_ip(client: ExtraHopClient, ip, active_from: str = None, active_until: str = None, limit: int = None):
    """Retrieve the device by IP address.

    Args:
        client: ExtraHop client to be used.
        ip: IP address of the device.
        active_from: Time the device was active from.
        active_until: Time the device was last active.
        limit: Number of devices to retrieve.

    Returns:
        Devices.
    """
    devices = client.device_search(name=None, ip=ip, mac=None, role=None, software=None, vendor=None, tag=None,
                                   discover_time=None, vlan=None, activity=None, operator="=", match_type="and",
                                   active_from=active_from, active_until=active_until, limit=limit, l3_only=True)
    if devices:
        return devices[0]
    else:
        raise DemistoException(f"Error the IP Address {ip} was not found in ExtraHop.")


def get_devices_by_ip_or_id(client: ExtraHopClient, devices_str, active_from: str = None, active_until: str = None,
                            limit: int = None, id_only: bool = False) -> List:
    """Retrieve the devices by IP address or ID.

    Args:
        client: Extrahop client to be used.
        devices_str: String os devices.
        active_from: Time the device was active from.
        active_until: Time the device was last active.
        limit: Number of devices to retrieve.
        id_only: Whether to retrieve devices by id only.

    Returns:
        List of devices.
    """
    devices = []
    for item in str(devices_str).split(","):
        if item.isdigit():
            if id_only:
                devices.append(int(item))
            else:
                device = client.get_device_by_id(item)
                devices.append(device)
        else:
            try:
                ip_address(item)
            except ValueError:
                raise DemistoException(f"Error parsing IP Address {item}")
            device = get_device_by_ip(client, item, active_from, active_until, limit)

            if id_only:
                devices.append(int(device["id"]))
            else:
                devices.append(device)

    return devices


def get_protocols(client: ExtraHopClient, ip_or_id, query_from, query_until) -> Dict:
    """Retrieve all the protocols for a device from the Reveal(X) in the given time range.

    Args:
        client: ExtraHop client to be used.
        ip_or_id: IP or ID of the object to get protocols for.
        query_from: Time since epoch to fetch the protocols.
        query_until: Time until epoch to fetch the protocols.

    Returns:
        Dictionory of client and server protocols.
    """
    device = get_devices_by_ip_or_id(client, ip_or_id)[0]
    api_id = int(device["id"])

    if device.get("analysis") == "discovery":
        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["markdown"],
            "Contents": (f"This Device is in Discovery Mode. Configure your [Analysis Priorities]"
                         f"(https://docs.extrahop.com/current/analysis_priorities/) or add this device to the "
                         f"[Watchlist](https://docs.extrahop.com/current/analysis-priorities-faq/"
                         f"#what-is-the-watchlist) manually with: `!extrahop-edit-watchlist add={api_id}`")
        })

    body = {
        "edge_annotations": ["protocols"],
        "from": query_from,
        "walks": [{
            "origins": [{
                "object_id": api_id,
                "object_type": "device"
            }],
            "steps": [{}]
        }]
    }
    if query_until:
        body["until"] = query_until

    activitymap = client.get_peers(body)

    client_protocols: DefaultDict[str, int] = defaultdict(int)
    server_protocols: DefaultDict[str, int] = defaultdict(int)
    for edge in activitymap["edges"]:
        if "annotations" in edge and "protocols" in edge.get("annotations"):
            for protocol_list in edge.get("annotations", {}).get("protocols"):
                proto_stack = format_protocol_stack(protocol_list["protocol"])
                if edge.get("from") == api_id:
                    client_protocols[proto_stack] += protocol_list["weight"]
                elif edge.get("to") == api_id:
                    server_protocols[proto_stack] += protocol_list["weight"]

    device["client_protocols"] = sort_protocols(client_protocols)
    device["server_protocols"] = sort_protocols(server_protocols)

    return device


def peers_get(client: ExtraHopClient, ip_or_id: Optional[Any], query_from: Optional[Any], query_until: Optional[Any],
              peer_role: Optional[Any], protocol: Optional[Any]) -> List:
    """Retrieve peers of a device from Reveal(X).

    Args:
        client: ExtraHop client to be used.
        ip_or_id: IP address or ID of the device.
        query_from: Beginning timestamp of the range.
        query_until: Ending timestamp of the range.
        peer_role: The role of the peer device in relation to the origin device.
        protocol: Communication protocol.

    Returns:
        List of peers of the device.
    """
    device = get_devices_by_ip_or_id(client, ip_or_id)[0]
    api_id = int(device["id"])

    if device["analysis"] == "discovery":
        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["markdown"],
            "Contents": (f"This Device is in Discovery Mode. Configure your [Analysis Priorities]"
                         f"(https://docs.extrahop.com/current/analysis_priorities/) or add this device to the "
                         f"[Watchlist](https://docs.extrahop.com/current/analysis-priorities-faq/"
                         f"#what-is-the-watchlist) manually with: `!extrahop-edit-watchlist add={api_id}`")})

    body = {
        "edge_annotations": ["protocols"],
        "from": query_from,
        "walks": [{
            "origins": [{
                "object_id": api_id,
                "object_type": "device"
            }],
            "steps": [{
                "relationships": [{
                    "protocol": protocol,
                    "role": peer_role
                }]
            }]
        }]
    }
    if query_until:
        body["until"] = query_until

    activitymap = client.get_peers(body)

    peers: DefaultDict[str, dict] = defaultdict(lambda: {
        "weight": 0,
        "client_protocols": defaultdict(int),
        "server_protocols": defaultdict(int)
    })

    for edge in activitymap["edges"]:
        if edge["to"] == api_id:
            peer_id = edge["from"]
            role_key = "client_protocols"
        else:
            peer_id = edge["to"]
            role_key = "server_protocols"

        peers[peer_id]["weight"] += edge["weight"]

        # add protocols
        if "annotations" in edge and "protocols" in edge["annotations"]:
            for protocol_list in edge["annotations"]["protocols"]:
                proto_stack = format_protocol_stack(protocol_list["protocol"])
                peers[peer_id][role_key][proto_stack] += protocol_list["weight"]

    peer_devices = []
    peer_ids_by_weight = [peer[0] for peer in sorted(peers.items(), key=lambda x: x[1]["weight"], reverse=True)]
    # Lookup each peer device by id
    for peer_id in peer_ids_by_weight:
        device = client.get_device_by_id(peer_id)
        if peer_role in ("any", "client"):
            device["client_protocols"] = sort_protocols(peers[peer_id]["client_protocols"])
        if peer_role in ("any", "server"):
            device["server_protocols"] = sort_protocols(peers[peer_id]["server_protocols"])
        peer_devices.append(device)
    return peer_devices


def get_activity_map(client: ExtraHopClient, ip_or_id: Optional[str], time_interval: Optional[Any],
                     from_time: Optional[Any], until_time: Optional[Any], peer_role: str, protocol: str,
                     server_url: str):
    """Retrieve the activity map link for a device from Reveal(X).

    Args:
        client: ExtraHop client to be used.
        ip_or_id: The IP Address or ExtraHop API ID of the source device to get an activity map.
        time_interval: The time interval of the live activity map.
        from_time: The beginning timestamp of a fixed time range.
        until_time: The ending timestamp of a fixed time range.
        peer_role: The role of the peer devices in relation to the source device.
        protocol: The protocol over which the source device is communicating.
        server_url: Server URL.

    Returns:
        Activity map link.
    """
    device = get_devices_by_ip_or_id(client, ip_or_id)[0]

    time_intervals = {
        "30 minutes": (30, "MIN"),
        "6 hours": (6, "HR"),
        "1 day": (1, "DAY"),
        "1 week": (1, "WK")
    }

    if from_time or until_time:
        if from_time and until_time:
            interval = "DT"
            start = from_time
            end = until_time
        else:
            raise ValueError(
                "When using a fixed time range both from_time and until_time timestamps need to be provided.")
    else:
        start, interval = time_intervals.get(time_interval, (30, "MIN"))  # type: ignore
        end = 0

    activity_map_params = {
        "server": server_url,
        "app_id": client.get_appliance_uuids()[device.get("node_id")],
        "disc_id": device.get("discovery_id"),
        "start": start,
        "interval": interval,
        "obj": "device",
        "proto": protocol,
        "role": peer_role,
        "end": end
    }

    activity_map_link_format = ("{server}/extrahop/#/activitymaps"
                                "?appliance_id={app_id}"
                                "&discovery_id={disc_id}"
                                "&from={start}"
                                "&interval_type={interval}"
                                "&object_type={obj}"
                                "&protocol={proto}"
                                "&role={role}"
                                "&until={end}")

    return activity_map_link_format.format(**activity_map_params)


def prepare_devices_get_output(response: List, appliance_uuids: List, server_url: str) -> str:
    """Prepare human-readable output for watchlist-get command.

    Args:
        appliance_uuids: UUID of the appliance.
        response: Response from the API.
        server_url: Server URL.

    Returns:
        markdown string to be displayed in the war room.
    """
    hr_outputs = []
    headers = ["Display Name", "IP Address", "MAC Address", "Role", "Vendor", "URL"]
    for device in response:
        hr = {
            "Display Name": device.get("display_name"),
            "IP Address": device.get("ipaddr4", device.get("ipaddr6")),
            "MAC Address": device.get("macaddr"),
            "Role": device.get("role"),
            "Vendor": device.get("vendor")
        }

        device_url = f'{server_url}/extrahop/#/metrics/devices/{appliance_uuids[device.get("node_id")]}.' \
                     f'{device.get("discovery_id")}/overview/'
        hr["URL"] = f"[View Device in ExtraHop]({device_url})"
        device["url"] = device_url

        if "client_protocols" in device or "server_protocols" in device:
            hr["Protocols"] = {}

            # re-arrange headers to add protocol information
            headers = ["Display Name", "IP Address", "MAC Address", "Role", "Protocols", "URL", "Vendor"]
            if "client_protocols" in device:
                hr["Protocols"]["Client"] = ", ".join(device.get("client_protocols", []))
            if "server_protocols" in device:
                hr["Protocols"]["Server"] = ", ".join(device.get("server_protocols", []))
        hr_outputs.append(hr)
    if not len(response):
        return "No Devices found"

    return tableToMarkdown("Device Details:\n", hr_outputs, headers=headers, removeNull=True)


def prepare_protocol_get_output(device, appliance_uuids, server_url) -> str:
    """Prepare human-readable output for protocol-get command.

    Args:
        device: The device data received from API.
        appliance_uuids: UUID of the appliance.
        server_url: Server URL.

    Returns:
        Markdown string to be displayed in the war room.
    """
    if not device.get("client_protocols") and not device.get("server_protocols"):
        return "No Protocol activity found"
    device_url = f'{server_url}/extrahop/#/metrics/devices/{appliance_uuids[device.get("node_id")]}.' \
                 f'{device.get("discovery_id")}/overview/'
    hr_outputs = {
        "Display Name": device.get("display_name"),
        "IP Address": device.get("ipaddr4", device.get("ipaddr6")),
        "MAC Address": device.get("macaddr"),
        "Protocols (Client)": ", ".join(device.get("client_protocols", [])),
        "Protocols (Server)": ", ".join(device.get("server_protocols", [])),
        "Role": device.get("role"),
        "Vendor": device.get("vendor"),
        "URL": f"[View Device in ExtraHop]({device_url})"
    }
    device["url"] = device_url

    headers = ["Display Name", "IP Address", "MAC Address",
               "Protocols (Client)", "Protocols (Server)", "Role", "Vendor", "URL"]

    return tableToMarkdown("Device Activity Found:\n", hr_outputs, headers=headers, removeNull=True)


def prepare_activity_map_link_output(activity_map_link: str) -> str:
    """Prepare human-readable output for activity-map-get command.

    Args:
        activity_map_link: Live link of an activity map.

    Returns:
        markdown string to be displayed in the war room.
    """
    return f"[View Live Activity Map in ExtraHop]({activity_map_link})"


def prepare_alert_rules_get_output(alerts: Dict) -> str:
    """Prepare human-readable output for get-alert-rules command.

    Args:
        alerts: List of alert response from the API.

    Returns:
        markdown string to be displayed in the war room.
    """
    if len(alerts) == 0:
        return "No Alerts were found."

    return tableToMarkdown(f"Found {len(alerts)} Alert(s)", alerts, headerTransform=string_to_table_header,
                           removeNull=True)


def prepare_metrics_list_output(response: Dict) -> str:
    """Prepare human-readable output for metrics-list command.

    Args:
        response: List of metrics response from the API.

    Returns:
        markdown string to be displayed in the war room.
    """
    hr_output = {
        "Cycle": response.get("cycle"),
        "Node ID": response.get("node_id"),
        "Clock": response.get("clock"),
        "From Time": response.get("from"),
        "Until Time": response.get("until"),
        "Stats": response.get("stats")
    }

    headers = ["Cycle", "Node ID", "Clock", "From Time", "Until Time", "Stats"]

    return tableToMarkdown("Metrics Found:\n", hr_output, headers=headers, removeNull=True)


def parse_location_header(location: str) -> str:
    """Retrieve the tag_id from the location field in header.

    Args:
        location: The location field in the header of the response received.

    Returns:
        The tag ID of the new created tag.
    """
    if location:
        last_slash_index = location.rindex('/') + 1
        tag_id = location[last_slash_index:]
        if tag_id.isdigit():
            return tag_id
    # return error in any other case
    raise DemistoException("Error unable to parse ExtraHop API response location header.")


def devices_tag(client: ExtraHopClient, tag: str, add: str, remove: str) -> None:
    """Tag or untag devices with the given tag name.

    Args:
        client: ExtraHop client to be used.
        tag: The tag which is added or removed from the devices.
        add: The list of IP or device ID to add tag.
        remove: The list of IP or device ID to remove tag.
    """
    body = {}
    if add:
        body["assign"] = get_devices_by_ip_or_id(client, add, id_only=True)
    if remove:
        body["unassign"] = get_devices_by_ip_or_id(client, remove, id_only=True)

    all_tags = client.get_all_tags()
    for current_tag in all_tags:
        if current_tag["name"] == tag:
            tag_id = current_tag["id"]
            break
    else:
        if remove and not add:
            raise DemistoException(f"The tag {tag} does not exist, nothing to remove.")

        tag_create_res = client.create_new_tag(data={"name": tag})
        tag_location = tag_create_res.headers.get('location')
        tag_id = parse_location_header(tag_location)

    client.tag_untag_devices(tag_id, data=body)


def prepare_list_detections_output(detections) -> str:
    """Prepare human-readable output for list-detections command.

    Args:
        detections: List of detection response from the API.

    Returns:
        markdown string to be displayed in the war room.
    """
    hr_outputs = []
    headers = ["Detection ID", "Risk Score", "Description", "Categories", "Status", "Resolution", "Start Time"]
    for detection in detections:
        hr_output = {
            "Detection ID": detection.get("id"),
            "Risk Score": detection.get("risk_score"),
            "Description": detection.get("description"),
            "Categories": detection.get("categories"),
            "Status": detection.get("status"),
            "Resolution": detection.get("resolution"),
            "Start Time": detection.get("start_time")
        }
        hr_outputs.append(hr_output)

    return tableToMarkdown(f"Found {len(hr_outputs)} Detection(s)", hr_outputs, headers=headers, removeNull=True)


""" COMMAND FUNCTIONS """


def validate_fetch_incidents_params(params: dict, last_run: dict) -> Dict:
    """
    Validate the parameter list for fetch incidents.

    Args:
        params: Dictionary containing demisto configuration parameters
        last_run: last run returned by function demisto.getLastRun

    Returns:
        Dictionary containing validated configuration parameters in proper format.
    """

    first_fetch = arg_to_datetime(params.get('first_fetch', FIRST_FETCH))
    detection_start_time = int(first_fetch.timestamp() * 1000)  # type: ignore

    if last_run and 'detection_start_time' in last_run:
        detection_start_time = last_run.get('detection_start_time')  # type: ignore

    offset = 0
    if last_run and 'offset' in last_run:
        offset = last_run.get("offset")  # type: ignore

    return {
        'detection_start_time': detection_start_time,
        'offset': offset
    }


def append_participant_device_data(client: ExtraHopClient, detections: CommandResults) -> CommandResults:
    """Append the device data of the participants present in the detection.

    Args:
        client: ExtraHop client to be used.
        detections: The command result object of detection data fetched from ExtraHop.

    Returns:
        CommandResult object with device data of the participants.
    """
    for detection in detections.outputs:  # type: ignore
        detection["device_data"] = []
        for participant in detection.get("participants", []):
            if participant.get("object_type") == "device":
                if not participant.get("object_id"):
                    continue
                object_id = participant.get("object_id")
                device_data = client.get_device_by_id(object_id, (404, 200, 204, 201))

            else:
                if not participant.get("object_value"):
                    continue
                ip = participant.get("object_value")
                device_data = client.device_search(name=None, ip=ip, mac=None, role=None, software=None, vendor=None,
                                                   tag=None, discover_time=None, vlan=None, activity=None, operator="=",
                                                   match_type="and", active_from=None, active_until=None, limit=None,
                                                   l3_only=True)
            if device_data:
                detection["device_data"].append(device_data)
    return detections


def fetch_extrahop_detections(client: ExtraHopClient, advanced_filter: Dict, last_run: Dict, on_cloud: bool) -> \
        Tuple[List, Dict]:
    """Fetch detections from ExtraHop according to the given filter.

    Args:
        client:ExtraHop client to be used.
        advanced_filter: The advanced_filter given by the user to filter out the required detections.
        last_run: Last run returned by function demisto.getLastRun
        on_cloud: Indicator for the instance hosted on cloud.

    Returns:
        List of incidents to be pushed into XSOAR.
    """
    try:
        already_fetched: List[str] = last_run.get('already_fetched', [])
        incidents: List[Dict] = []
        detection_start_time = advanced_filter["mod_time"]

        detections = detections_list_command(client, {}, on_cloud=on_cloud, advanced_filter=advanced_filter)

        if detections.outputs:
            detections = append_participant_device_data(client, detections)

            for detection in detections.outputs:  # type: ignore
                detection_id = detection.get("id")
                if detection_id not in already_fetched:
                    detection.update(get_mirroring())
                    incident = {
                        'name': str(detection.get("type", "")),
                        'occurred': datetime.utcfromtimestamp(detection['start_time'] / 1000).strftime(
                            DATE_FORMAT),
                        'severity': next((severity for range_str, severity in TICKET_SEVERITY.items() if
                                          detection.get("risk_score") in range(*map(int, range_str.split("-")))), None),
                        'rawJSON': json.dumps(detection)
                    }
                    incidents.append(incident)
                    already_fetched.append(detection_id)

                else:
                    demisto.info(f"Extrahop already fetched detection with id: {detection_id}")

        if len(incidents) < advanced_filter["limit"]:
            offset = 0
            detection_start_time = \
                detections.outputs[-1]["mod_time"] + 1 if incidents else detection_start_time  # type: ignore
        else:
            offset = advanced_filter["offset"] + len(incidents)

    except Exception as error:
        raise DemistoException(f"extrahop: exception occurred {str(error)}")

    demisto.info(f"Extrahop fetched {len(incidents)} incidents where the advanced filter is {advanced_filter}")

    last_run["detection_start_time"] = int(detection_start_time)
    last_run["offset"] = offset
    last_run["already_fetched"] = already_fetched
    return incidents, last_run


def fetch_incidents(client: ExtraHopClient, params: Dict, last_run: Dict, on_cloud: bool):
    """Fetch the specified ExtraHop entity and push into XSOAR.

     Args:
        client: ExtraHop client to be used.
        params: Integration configuration parameters.
        last_run: The last_run dictionary having the state of previous cycle.
        on_cloud: Indicator for the instance hosted on cloud.
    """
    demisto.info(f"Extrahop fetch_incidents invoked with advanced_filter: {params.get('advanced_filter', '')}, "
                 f"first_fetch: {params.get('first_fetch', '')} and last_run: {last_run}")
    fetch_params = validate_fetch_incidents_params(params, last_run)

    now = datetime.now()
    next_day = now + timedelta(days=1)
    if last_run.get("version_recheck_time", 1581852287000) < int(now.timestamp() * 1000):
        version = get_extrahop_server_version(client)
        last_run["version_recheck_time"] = int(next_day.timestamp() * 1000)
        if version < "9.3.0":
            raise DemistoException(
                "This integration works with ExtraHop firmware version greater than or equal to 9.3.0")

    advanced_filter = params.get("advanced_filter")
    if advanced_filter and advanced_filter.strip():
        try:
            _filter = json.loads(advanced_filter)
            add_default_category_for_filter_of_detection_list(_filter)
        except json.JSONDecodeError as error:
            raise ValueError("Invalid JSON string provided for advanced filter.") from error
    else:
        _filter = {"categories": ["sec.attack"]}

    advanced_filter = {"filter": _filter, "mod_time": fetch_params["detection_start_time"], "until": 0,
                       "limit": MAX_FETCH, "offset": fetch_params["offset"],
                       "sort": [{"direction": "asc", "field": "mod_time"}]}

    incidents, next_run = fetch_extrahop_detections(client, advanced_filter, last_run, on_cloud)
    demisto.info(f"Extrahop next_run is {next_run}")
    return incidents, next_run


def watchlist_get_command(client: ExtraHopClient, on_cloud: bool) -> CommandResults:
    """Retrieve all the devices on the watchlist in Reveal(X).

    Args:
        client: ExtraHop client to be used.
        on_cloud: Check if ExtraHop instance is on cloud.

    Returns:
        CommandResult object
    """
    response = client.get_watchlist()
    appliance_uuids = client.get_appliance_uuids()

    server_url = client._base_url

    if on_cloud:
        server_url = remove_api_from_base_url(server_url)

    readable_output = prepare_devices_get_output(response, appliance_uuids, server_url)

    return CommandResults(
        outputs_prefix="ExtraHop.Device",
        outputs_key_field="id",
        outputs=remove_empty_elements_from_response(response),
        readable_output=readable_output,
        raw_response=response,
    )


def peers_get_command(client: ExtraHopClient, args: Dict[str, Any], on_cloud: bool) -> CommandResults:
    """Retrieve all the peers for a device from the Reveal(X).

    Args:
        client: ExtraHop client to be used.
        args: arguments obtained from demisto.args().
        on_cloud: Check if ExtraHop instance is on cloud.

    Returns:
        CommandResult object
    """
    ip_or_id = args.get("ip_or_id")
    query_from = args.get("query_from", "-30m")
    query_until = args.get("query_until")
    peer_role = args.get("peer_role")
    protocol = args.get("protocol")

    validate_peers_get_arguments(peer_role, protocol)

    peer_devices = peers_get(client, ip_or_id, query_from, query_until, peer_role, protocol)
    appliance_uuids = client.get_appliance_uuids()

    server_url = client._base_url

    if on_cloud:
        server_url = remove_api_from_base_url(server_url)

    readable_output = prepare_devices_get_output(peer_devices, appliance_uuids, server_url)

    return CommandResults(
        outputs_prefix="ExtraHop.Device",
        outputs_key_field="id",
        outputs=remove_empty_elements_from_response(peer_devices),
        readable_output=readable_output,
        raw_response=peer_devices,
    )


def devices_search_command(client: ExtraHopClient, args: Dict[str, Any], on_cloud: bool) -> CommandResults:
    """Retrieve the devices from Reveal(X).

    Args:
        client: ExtraHop client to be used:
        args: Arguments obtained from demisto.args().
        on_cloud: Check if ExtraHop instance is on cloud.

    Returns:
        CommandResult object
    """
    name = args.get("name")
    ip = args.get("ip")
    mac = args.get("mac")
    role = args.get("role")
    software = args.get("software")
    vendor = args.get("vendor")
    tag = args.get("tag")
    discover_time = args.get("discover_time")
    vlan = args.get("vlan")
    activity = args.get("activity")
    operator = args.get("operator")
    match_type = args.get("match_type")
    active_from = args.get("active_from")
    active_until = args.get("active_until")
    limit = args.get("limit", 10)
    l3_only = args.get("l3_only", True)

    validate_device_search_arguments(role, software, vendor, activity, operator, match_type, l3_only)

    devices = client.device_search(name, ip, mac, role, software, vendor, tag, discover_time, vlan, activity, operator,
                                   match_type, active_from, active_until, limit, l3_only)
    appliance_uuids = client.get_appliance_uuids()

    server_url = client._base_url

    if on_cloud:
        server_url = remove_api_from_base_url(server_url)

    readable_output = prepare_devices_get_output(devices, appliance_uuids, server_url)
    return CommandResults(
        outputs_prefix="ExtraHop.Device",
        outputs_key_field="id",
        outputs=remove_empty_elements_from_response(devices),
        readable_output=readable_output,
        raw_response=devices,
    )


def protocols_get_command(client: ExtraHopClient, args: Dict[str, Any], on_cloud: bool) -> CommandResults:
    """Retrieve all active network protocols for a device from Reveal(x).

    Args:
        client: ExtraHop client to be used.
        args: Arguments obtained from demisto.args()
        on_cloud: Check if ExtraHop instance is on cloud.

    Returns:
        CommandResult object
    """
    ip_or_id = args.get("ip_or_id")
    query_from = args.get("query_from")
    query_until = args.get("query_until")

    device = get_protocols(client, ip_or_id, query_from, query_until)

    server_url = client._base_url
    if on_cloud:
        server_url = remove_api_from_base_url(server_url)

    appliance_uuids = client.get_appliance_uuids()
    readable_output = prepare_protocol_get_output(device, appliance_uuids, server_url)

    return CommandResults(
        outputs_prefix="ExtraHop.Device",
        outputs_key_field="id",
        outputs=remove_empty_elements_from_response(device),
        readable_output=readable_output,
        raw_response=device,
    )


def activity_map_get_command(client: ExtraHopClient, args: Dict[str, Any], on_cloud: bool) -> CommandResults:
    """Retrieve the activity of a device from Reveal(x).

    Args:
        client: ExtraHop client to be used.
        args: Arguments obtained from demisto.args()
        on_cloud: Check if ExtraHop instance is on cloud.

    Returns:
        CommandResult object
    """
    ip_or_id = args.get("ip_or_id")
    time_interval = args.get("time_interval", "30 minutes")
    from_time = args.get("from_time")
    until_time = args.get("until_time")
    peer_role = args.get("peer_role", "any")
    protocol = args.get("protocol", "any")

    validate_activity_map_get_arguments(ip_or_id, time_interval, from_time, until_time, peer_role, protocol)

    server_url = client._base_url

    if on_cloud:
        server_url = remove_api_from_base_url(server_url)

    activity_map_link = get_activity_map(client, ip_or_id, time_interval, from_time, until_time, peer_role, protocol,
                                         server_url)

    context = {"url": activity_map_link}

    readable_output = prepare_activity_map_link_output(activity_map_link)

    return CommandResults(
        outputs_prefix="ExtraHop.ActivityMap",
        outputs_key_field="url",
        outputs=remove_empty_elements_from_response(context),
        readable_output=readable_output,
        raw_response=context,
    )


def alerts_rules_get_command(client: ExtraHopClient) -> CommandResults:
    """Retrieve all the available alerts from the ExtraHop Reveal(X).

    Args:
        client: ExtraHop client to be used.

    Returns:
        CommandResult object
    """
    result = client.get_alert_rules()
    readable_output = prepare_alert_rules_get_output(result)
    return CommandResults(
        outputs_prefix="ExtraHop.Alert",
        outputs_key_field="id",
        outputs=remove_empty_elements_from_response(result),
        readable_output=readable_output,
        raw_response=result,
    )


def packets_search_command(client: ExtraHopClient, args: Dict[str, Any]) -> Union[str, Dict]:
    """Retrieve the specific packets from Reveal(X).

    Args:
        client: ExtraHop client to be used.
        args: Arguments obtained from demisto.args().

    Returns:
        File containing the packets.
    """
    output = args.get("output", "pcap")
    limit_bytes = args.get("limit_bytes", "10MB")
    limit_search_duration = args.get("limit_search_duration", "5m")
    query_from = args.get("query_from", "-10m")
    query_until = args.get("query_until")
    bpf = args.get("bpf")
    ip1 = args.get("ip1")
    port1 = args.get("port1")
    ip2 = args.get("ip2")
    port2 = args.get("port2")

    validate_packets_search_arguments(output)

    response = client.packets_search(output, limit_bytes, limit_search_duration, query_from, query_until, bpf, ip1,
                                     port1, ip2, port2)

    if response.status_code == 204:
        return "Search matched no packets."
    filename_header = response.headers.get("content-disposition")
    f_attr = "filename="
    if filename_header and f_attr in filename_header:
        quoted_filename = filename_header[filename_header.index(f_attr) + len(f_attr):]
        filename = quoted_filename.replace('"', "")
    else:
        raise DemistoException("Error filename could not be found in response header.")

    return fileResult(filename, response.content)


def ticket_track_command(client: ExtraHopClient, args: Dict[str, Any]) -> CommandResults:
    """Link a Reveal(x) detection to a Demisto Investigation.

    Args:
        client: ExtraHop client to be used.
        args: Arguments received for the command.
    Returns:
        CommandResult object
    """
    incident_id = args.get("incident_id")
    detection_id = args.get("detection_id", "")
    incident_owner = args.get("incident_owner")
    incident_status = args.get("incident_status", "")
    incident_close_reason = args.get("incident_close_reason")

    validate_ticket_track_arguments(incident_status)

    detection_status = {
        "ticket_id": incident_id,
        "status": TICKET_STATUS_MAP.get(incident_status),
        "assignee": incident_owner or None
    }

    # Only set Resolution if the incident is closed
    if detection_status["status"] == "closed" and incident_close_reason:
        if incident_close_reason == "Resolved":
            detection_status["resolution"] = "action_taken"
        elif incident_close_reason in {"False Positive", "Duplicate"}:
            detection_status["resolution"] = "no_action_taken"

    client.patch_detections(detection_id, detection_status)

    readable_output = f"Successfully linked detection({detection_id}) with incident({incident_id})"
    output = {
        "TicketId": incident_id
    }  # type: dict

    return CommandResults(
        outputs_prefix="ExtraHop",
        outputs_key_field="TicketId",
        outputs=remove_empty_elements(output),
        readable_output=readable_output,
        raw_response=output,
    )


def devices_tag_command(client: ExtraHopClient, args: Dict[str, Any]) -> str:
    """Add or remove a tag from devices in Reveal(x).

    Args:
        client: ExtraHop client to be used.
        args: Arguments received for the command.

    Returns:
        CommandResult object
    """
    tag = args.get('tag', "")
    add = args.get('add', "")
    remove = args.get('remove', "")

    validate_add_and_remove_arguments(add, remove)

    devices_tag(client, tag, add, remove)

    return "Successfully tagged untagged the device/s."


def create_or_edit_alert_rule_command(client: ExtraHopClient, args: Dict[str, Any]) -> CommandResults:
    """Create or update alert rule from Reveal(x).

    Args:
        client: ExtraHop client to be used.
        args: Arguments received for the command.

    Returns:
        CommandResult object.
    """
    apply_all = argToBoolean(args.get("apply_all", False))
    disabled = argToBoolean(args.get("disabled", False))
    name = args.get("name")
    notify_snmp = argToBoolean(args.get("notify_snmp", False))
    refire_interval = args.get("refire_interval", 0)
    severity = args.get("severity", 0)
    alert_type = args.get("type")
    alert_id = args.get("alert_id")

    validate_create_or_update_alert_rule_arguments(refire_interval, severity, alert_type)

    # Prepare request body for alert-rule.
    data = {
        "apply_all": apply_all,
        "disabled": disabled,
        "name": name,
        "notify_snmp": notify_snmp,
        "refire_interval": int(refire_interval),
        "severity": int(severity),
        "type": alert_type
    }

    # For alertType = threshold.
    if alert_type == "threshold":
        field_name = args.get("field_name")
        field_name2 = args.get("field_name2")
        field_op = args.get("field_op")
        interval_length = args.get("interval_length", 0)
        operand = args.get("operand")
        operator = args.get("operator")
        param = args.get("param")
        param2 = args.get("param2")
        stat_name = args.get("stat_name")
        units = args.get("units")
        validate_threshold_alert_rule_arguments(interval_length, operator, units)
        data["interval_length"] = int(interval_length)
        data["operator"] = operator
        data["units"] = units

        if field_name:
            data["field_name"] = field_name
        if field_name2:
            data["field_name2"] = field_name2
        if field_op:
            data["field_op"] = field_op
        if operand:
            data["operand"] = operand
        if param:
            data["param"] = param
        if param2:
            data["param2"] = param2
        if stat_name:
            data["stat_name"] = stat_name

    elif alert_type == "detection":
        if object_type := args.get("object_type"):
            if object_type not in VALID_ALERT_RULE_OBJECT_TYPES:
                raise InvalidValueError("object_type", object_type, VALID_ALERT_RULE_OBJECT_TYPES)
            data["object_type"] = object_type
        if protocols := argToList(args.get("protocols")):
            data["protocols"] = protocols

    if alert_id:
        client.update_alert_rule(alert_id, data)
        return CommandResults(
            readable_output="Successfully updated alert rule."
        )
    else:
        client.create_alert_rule(data)
        return CommandResults(

            readable_output="Successfully created alert rule."
        )


def watchlist_edit_command(client: ExtraHopClient, args: Dict[str, Any]) -> CommandResults:
    """Add or remove devices from the watchlist in Reveal(x).
    Args:
        client: ExtraHop client to be used.
        args: Arguments obtained from demisto.args().
    Returns:
        CommandResults object.
    """
    add = args.get("add", "")
    remove = args.get("remove", "")
    validate_add_and_remove_arguments(add, remove)
    body = {}
    hr_outputs = ""

    if add:
        body["assign"] = get_devices_by_ip_or_id(client, add, id_only=True)
        hr_outputs += f"Successfully added new devices({add}) in the watchlist \n"
    if remove:
        hr_outputs += f"Successfully removed devices({remove}) from the watchlist"
        body['unassign'] = get_devices_by_ip_or_id(client, remove, id_only=True)

    client.edit_watchlist(body)

    return CommandResults(
        readable_output=hr_outputs
    )


def metrics_list_command(client: ExtraHopClient, args=None, advanced_filter: str = None) -> CommandResults:
    """Retrieve metric information collected about every object from the Reveal(X).

    Args:
        client: ExtraHop client to be used.
        args: Arguments obtained from demisto.args()
        advanced_filter: Advance filter to be used for fetching incidents.

    Returns:
        CommandResult object
    """

    # This snipper will work in case of the fetch incidents for metrics, when user provides advance filter.
    if args is None:
        args = {}
    if advanced_filter:
        try:
            body = json.loads(advanced_filter)  # type: ignore
        except json.JSONDecodeError:
            raise ValueError("Invalid json string provided for advanced filter.")
        validate_metrics_list_arguments(body)
    else:
        cycle = args.get("cycle")
        from_time = args.get("from_time")
        metric_category = args.get("metric_category")
        object_ids = argToList(args.get("object_ids"))
        object_ids = [arg_to_number(object_id) for object_id in object_ids]
        object_type = args.get("object_type")
        until_time = args.get("until_time")
        metric_specs = args.get("metric_specs")

        try:
            metric_specs_json = json.loads(metric_specs)  # type: ignore
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON string provided for metric specs.")

        body = {
            "cycle": cycle,
            "from": from_time,
            "until": until_time,
            "metric_category": metric_category,
            "metric_specs": metric_specs_json,
            "object_ids": object_ids,
            "object_type": object_type
        }
        validate_metrics_list_arguments(body)

    response = client.metrics_list(body)
    readable_output = prepare_metrics_list_output(response)

    return CommandResults(
        outputs_prefix="ExtraHop.Metrics",
        outputs=remove_empty_elements_from_response(response),
        readable_output=readable_output,
        raw_response=response,
    )


def detections_list_command(client: ExtraHopClient, args: Dict[str, Any], on_cloud=False,
                            advanced_filter=None) -> CommandResults:
    """Retrieve the detections from Reveal(X).

    Args:
        client: ExtraHop client to be used.
        args: Arguments obtained from demisto.args().
        advanced_filter: The advanced filter provided by user to fetch detections.
        on_cloud: Check if ExtraHop instance is on cloud.

    Returns:
        CommandResults object.
    """
    version = get_extrahop_server_version(client)
    if version < "9.3.0":
        raise DemistoException(
            "This integration works with ExtraHop firmware version greater than or equal to 9.3.0")

    body = {}
    if advanced_filter:
        body = advanced_filter

    else:
        filter_query = args.get("filter")
        from_time = arg_to_number(args.get("from"))
        limit = arg_to_number(args.get("limit"), "200")
        offset = arg_to_number(args.get("offset"))
        sort = args.get("sort")
        until_time = arg_to_number(args.get("until"))
        mod_time = arg_to_number(args.get("mod_time"))
        if filter_query and filter_query.strip():
            try:
                filter_query = json.loads(filter_query)
                add_default_category_for_filter_of_detection_list(filter_query)
                body["filter"] = filter_query
            except json.JSONDecodeError:
                raise ValueError("Invalid json string provided for filter.")
        else:
            body["filter"] = {"categories": ["sec.attack"]}

        if isinstance(from_time, int):
            body["from"] = from_time

        if isinstance(limit, int):
            body["limit"] = limit

        if isinstance(offset, int):
            body["offset"] = offset

        if sort:
            sort_list = []
            sort_on_field = sort.split(",")

            for sort in sort_on_field:
                try:
                    field, direction = sort.split(" ")
                except ValueError:
                    raise DemistoException("Incorrect input provided for argument \"sort\". Please follow the format "
                                           "mentioned in description.")

                if direction not in SORT_DIRECTION:
                    raise DemistoException("Incorrect input provided for argument \"sort\". Allowed values for "
                                           "direction are: " + ", ".join(SORT_DIRECTION))

                prepared_sort_dict = {"direction": direction, "field": field}
                sort_list.append(prepared_sort_dict)

            body["sort"] = sort_list

        if isinstance(until_time, int):
            body["until"] = until_time

        if isinstance(mod_time, int):
            body["mod_time"] = mod_time

    validate_detections_list_arguments(body)

    detections = client.detections_list(body)

    base_url = client._base_url
    if on_cloud:
        base_url = remove_api_from_base_url(base_url)
    for detection in detections:
        if detection.get("description"):
            detection["description"] = modify_description(base_url, detection.get("description"))
    readable_output = prepare_list_detections_output(detections)

    return CommandResults(
        outputs_prefix="ExtraHop.Detections",
        outputs_key_field="id",
        outputs=remove_empty_elements(detections),
        readable_output=readable_output,
        raw_response=detections,
    )


def get_mirroring() -> Dict:
    """Add mirroring related keys in an incident.

    Returns:
        A dictionary containing required key-value pairs for mirroring.
    """
    return {
        'mirror_direction': "In",
        'mirror_instance': demisto.integrationInstance(),
    }


def get_modified_remote_data_command(client, args: Dict[str, Any],
                                     params: Dict) -> GetModifiedRemoteDataResponse:
    """Retrieve the IDs of the incidents which are updated since the last updated.

    Args:
        client: XSOAR client to use.
        args:
            lastUpdate: When was the last time we retrieved data.
        params: The integration configuration parameters.

    Returns:
        GetModifiedRemoteDataResponse: List of incidents IDs which are modified since the last update.
    """
    # Retrieve the arguments passed with the command.
    command_args = GetModifiedRemoteDataArgs(args)

    # Parse the last update date got from the command arguments.
    command_last_run_date = dateparser.parse(command_args.last_update, settings={'TIMEZONE': 'UTC'})

    demisto.debug(f'Last update date of get-modified-remote-data command is {command_last_run_date}.')

    # Convert the datetime object to epoch as the API requires the time in epoch format.
    body = {
        "mod_time": date_to_timestamp(command_last_run_date),
        # End time for the API call will be current time.
        "until": 0,
        "offset": 0,
        "sort": [{"direction": "asc", "field": "mod_time"}],
        "limit": MAX_FETCH,
    }

    advanced_filter = params.get("advanced_filter")
    try:
        advanced_filter = json.loads(advanced_filter)  # type: ignore
    except json.JSONDecodeError as error:
        raise ValueError("Invalid JSON string provided for advanced filter.") from error
    body["filter"] = advanced_filter

    len_of_incidents = 0
    updated_incident_ids = []

    while True:
        body["offset"] += len_of_incidents

        list_incidents_resp = client.detections_list(body)
        len_of_incidents = len(list_incidents_resp)

        if len_of_incidents == 0:
            break

        # Extract the IDs of the incidents.
        updated_incident_ids.extend([str(inc.get('id')) for inc in list_incidents_resp])

        if len(updated_incident_ids) >= 10000:
            break

    # Filter out None values if there are any.
    updated_incident_ids: List[str] = list(filter(None, updated_incident_ids))

    # Filter out any duplicate incident IDs.
    updated_incident_ids = list(set(updated_incident_ids))

    # At max 10,000 incidents should be updated.
    updated_incident_ids = updated_incident_ids[:10000]

    demisto.info(f'Extrahop Number of incidents modified between {body["mod_time"]} to {body["until"]} are '
                 f'{len(updated_incident_ids)}.')
    demisto.info(f'Extrahop List of modified incident ids between {body["mod_time"]} to {body["until"]} is '
                 f'{updated_incident_ids}.')

    return GetModifiedRemoteDataResponse(updated_incident_ids)


def get_remote_data_command(client, args: Dict[str, Any]) -> Union[str, GetRemoteDataResponse]:
    """Return the updated incident and updated entries.

    Args:
        client: XSOAR client to use.
        args:
            id: Incident ID to retrieve.

    Returns:
        First entry is the incident (which can be completely empty) and the new entries.
    """
    parsed_args = GetRemoteDataArgs(args)
    demisto.info(f"Extrahop get_remote_data_command invoked for {parsed_args.remote_incident_id}")
    detection = client.get_detections_by_id(parsed_args.remote_incident_id)
    return GetRemoteDataResponse(detection, [])


def test_module(client: ExtraHopClient) -> str:
    """Tests API connectivity and authentication.

    Returning "ok" indicates that the integration works like it is supposed to.
    Connection to the service is successful.

    Args:
        client: ExtraHop client to be used.

    Returns:
        "ok" if test passed, anything else will fail the test.
    """
    response = client.test_connection()
    version = get_extrahop_server_version(client)
    if version < "9.3.0":
        raise DemistoException("This integration works with ExtraHop firmware version greater than or equal to 9.3.0")
    if response:
        return "ok"
    raise ValueError("Failed to establish connection with provided credentials.")


def prepare_query_records_output(response: Dict) -> str:
    """
        prepare human-readable output for query-records command
    Args:
        response: List of records response from the API
    Returns:
        markdown string to be displayed in the war room
    """
    records = response.get("records", [])
    hr_table = []
    extrahop_context: Dict[str, Any] = {
        "ExtraHop": {
            "Record": []
        }
    }
    for record in records:
        hr_table.append(record["_source"])
        extrahop_context['ExtraHop']['Record'].append(
            createContext(record, keyTransform=string_to_context_key, removeNull=True))
    if len(records) == 0:
        return "No records were found"
    return tableToMarkdown("showing {results} out of {total} Record(s) Found.".format(
        total=response.get("total", 0), results=len(records)), hr_table)


def query_records_command(client: ExtraHopClient, args: Dict[str, Any]) -> CommandResults:
    """Query records command is fetched records in the given timeline from the ExtraHop instance.
    Args:
        client: ExtraHop client to be used.
        args: Arguments received for the command.
    Returns:
        Command Result object.
    """
    query_from = args.get("query_from")
    query_until = args.get("query_until")
    limit = args.get("limit")
    offset = args.get("offset")
    field1 = args.get("field1")
    operator1 = args.get("operator1")
    value1 = args.get("value1")
    field2 = args.get("field2")
    operator2 = args.get("operator2")
    value2 = args.get("value2")
    match_type = args.get("match_type", "")
    specific_types = args.get("types")
    data: Dict = {}
    if specific_types:
        try:
            data["types"] = [
                f'~{rec_type.strip()}'
                for rec_type in specific_types.split(",")
            ]
        except Exception:
            raise DemistoException('Error parsing the types argument, expected a comma separated list of types.')
    if query_from:
        data["from"] = query_from
    if query_until:
        data["until"] = query_until
    if limit:
        if int(limit) > 1000:
            data["limit"] = 1000
            data['context_ttl'] = "30s"
        else:
            data["limit"] = int(limit)
    if offset:
        data["offset"] = int(offset)
    data['filter'] = {
        "operator": match_type,
        "rules": []
    }
    if field1:
        rule = {
            "field": field1,
            "operator": operator1,
            "operand": value1 or ""
        }
        data["filter"]["rules"].append(rule)
    if field2:
        rule = {
            "field": field2,
            "operator": operator2,
            "operand": value2 or ""
        }
        data["filter"]["rules"].append(rule)
    result = client.get_query_records(body=data)
    cursor = result.get("cursor")
    if cursor and result.get("total", 0) > data['limit']:
        additional_records = client.get_next_page_records(cursor).get("records", [])
        while (len(additional_records)) > 0:
            result["records"].extend(additional_records)
            additional_records = client.get_next_page_records(cursor).get("records", [])
    readable_output = prepare_query_records_output(result)
    return CommandResults(
        outputs_prefix="ExtraHop.Record",
        outputs_key_field="id",
        outputs=remove_empty_elements_from_response(result),
        readable_output=readable_output,
        raw_response=result
    )


def main():
    """Parse params and runs command functions."""
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    try:
        on_cloud = params.get("on_cloud", False)
        api_key = params.get("apikey")
        base_url = params.get("url").strip("/")
        client_id = params.get("client_id", "")
        client_secret = params.get("client_secret", "")
        verify_certificate = not params.get("insecure", False)
        use_proxy: bool = params.get('proxy', False)

        if on_cloud and (not client_id or not client_secret):
            raise DemistoException("If On Cloud is marked true, Client ID and Client Secret is required field.")

        client = ExtraHopClient(base_url=base_url,
                                api_key=api_key,
                                client_id=client_id,
                                client_secret=client_secret,
                                verify=verify_certificate,
                                use_proxy=use_proxy,
                                ok_codes=(200, 201, 204),
                                on_cloud=on_cloud)

        remove_nulls_from_dictionary(trim_spaces_from_args(args))

        demisto.info(f"Extrahop command being called is {command}")
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, params, last_run, on_cloud)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == "extrahop-watchlist-get":
            return_results(watchlist_get_command(client, on_cloud))
        elif command == "extrahop-peers-get":
            return_results(peers_get_command(client, args, on_cloud))
        elif command == "extrahop-devices-search":
            return_results(devices_search_command(client, args, on_cloud))
        elif command == "extrahop-protocols-get":
            return_results(protocols_get_command(client, args, on_cloud))
        elif command == "extrahop-activity-map-get":
            return_results(activity_map_get_command(client, args, on_cloud))
        elif command == "extrahop-alert-rules-get":
            return_results(alerts_rules_get_command(client))
        elif command == "extrahop-packets-search":
            return_results(packets_search_command(client, args))
        elif command == "extrahop-ticket-track":
            return_results(ticket_track_command(client, args))
        elif command == 'extrahop-devices-tag':
            return_results(devices_tag_command(client, args))
        elif command in ("extrahop-alert-rule-create", "extrahop-alert-rule-edit"):
            return_results(create_or_edit_alert_rule_command(client, args))
        elif command == "extrahop-watchlist-edit":
            return_results(watchlist_edit_command(client, args))
        elif command == "extrahop-metrics-list":
            return_results(metrics_list_command(client, args))
        elif command == "extrahop-detections-list":
            return_results(detections_list_command(client, args, on_cloud))
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args, params))

        # Deprecated commands.
        elif demisto.command() in ('extrahop-get-alert-rules', 'extrahop-get-alerts'):
            return_results(alerts_rules_get_command(client))
        elif demisto.command() == 'extrahop-query-records':  # Removed this command.
            return_results(query_records_command(client, args))
        elif demisto.command() == 'extrahop-device-search':
            return_results(devices_search_command(client, args, on_cloud))
        elif demisto.command() == 'extrahop-edit-watchlist':
            return_results(watchlist_edit_command(client, args))
        elif demisto.command() == 'extrahop-get-watchlist':
            return_results(watchlist_get_command(client, on_cloud))
        elif demisto.command() in ('extrahop-create-alert-rule', 'extrahop-create-alert'):
            return_results(create_or_edit_alert_rule_command(client, args))
        elif demisto.command() in ('extrahop-edit-alert-rule', 'extrahop-edit-alert'):
            return_results(create_or_edit_alert_rule_command(client, args))
        elif demisto.command() == 'extrahop-track-ticket':
            return_results(ticket_track_command(client, args))
        elif demisto.command() == 'extrahop-get-peers':
            return_results(peers_get_command(client, args, on_cloud))
        elif demisto.command() == 'extrahop-get-protocols':
            return_results(protocols_get_command(client, args, on_cloud))
        elif demisto.command() == 'extrahop-tag-devices':
            return_results(devices_tag_command(client, args))
        elif demisto.command() == 'extrahop-get-activity-map':
            return_results(activity_map_get_command(client, args, on_cloud))
        elif demisto.command() == 'extrahop-search-packets':
            return_results(packets_search_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as error:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(error)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
