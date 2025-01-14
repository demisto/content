import demistomock as demisto
from CommonServerPython import *

from datetime import datetime, UTC
from typing import Any

import json

# Disable insecure warnings
import urllib3
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, verify, client_id, token, proxy):
        """
        Constructor which adds the authentication headers required by IllusionBLACK external API
        Args:
            base_url: IllusionBLACK URL. For example: https://experience.illusionblack.com
            verify: Allow insecure SSL
            client_id:
            token:
            proxy:
        """
        headers = {"x-client-id": client_id, "x-client-auth": token}
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def ping(self):
        """
        Initiates a HTTP Request to IllusionBLACK test endpoint /ping
        """
        response = self._http_request(
            method="GET",
            url_suffix="/ping",
            ok_codes=(200,)
        )
        return response.get("message", "error")

    def get_ad_decoys(self):
        """
        Gets a list of Active Directory (AD) user decoys from IllusionBLACK
        Returns: A tuple containing the response in human readable, context data and raw response formats
        """
        response = self._http_request(
            method="GET",
            url_suffix="/decoy/users",
            ok_codes=(200,)
        )
        users = response["items"]
        return (
            tableToMarkdown(
                "IllusionBLACK AD Decoys",
                users,
                headerTransform=lambda s: " ".join([w.capitalize() for w in s.split("_")])
            ),
            {"IllusionBlack.AdDecoy(val.user_name==obj.user_name)": users},
            users
        )

    def get_network_decoys(self):
        """
        Gets a list of network decoys from IllusionBLACK and enriches the data with the list of services enabled.
        Returns:A tuple containing the response in human readable, context data and raw response formats
        """
        response = self._http_request(
            method="GET",
            url_suffix="/decoy/hosts",
            ok_codes=(200,)
        )
        hosts: list = response["items"]
        for h in hosts:
            h["services"] = ", ".join(h["services"])
        return (
            tableToMarkdown("IllusionBLACK Network Decoys", hosts, headerTransform=lambda s: s.capitalize()),
            {"IllusionBlack.NetworkDecoy(val.name==obj.name)": hosts},
            hosts
        )

    def get_ti_decoys(self):
        """
        Gets a list of Threat Intelligence decoys from IllusionBLACK.
        Returns: A tuple containing the response in human readable, context data and raw response formats
        """
        response = self._http_request(
            method="GET",
            url_suffix="/decoy/recon",
            ok_codes=(200,)
        )
        recon_decoys = response["items"]
        return (
            tableToMarkdown(
                "IllusionBLACK TI Decoys",
                recon_decoys,
                headerTransform=lambda s: " ".join([w.capitalize() for w in s.split("_")])
            ),
            {"IllusionBlack.TIDecoy(val.name==obj.name)": recon_decoys},
            recon_decoys
        )

    def is_host_decoy(self, host):
        """
        Checks if the host is an IllusionBLACK network decoy
        Args:
            host: The name of the entity For example: SMB-12
        Returns: True if host is a decoy else False
        """
        response = self._http_request(
            method="GET",
            url_suffix="/decoy/hosts",
            ok_codes=(200,)
        )
        hosts: list = response["items"]
        for decoy_host in hosts:
            if host == decoy_host["name"]:
                return "True", {"IllusionBlack.IsHostDecoy": {"Host": host, "Value": True}}
        return "False", {"IllusionBlack.IsHostDecoy": {"Host": host, "Value": False}}

    def is_user_decoy(self, user):
        """
        Checks if the user is an IllusionBLACK AD user decoy
        Args:
            user: The user name of the AD user to check
        Returns: True if user is a decoy else False
        """
        response = self._http_request(
            method="GET",
            url_suffix="/decoy/users",
            ok_codes=(200,)
        )
        users: list = response["items"]
        for decoy_user in users:
            if user.lower() == decoy_user["user_name"]:
                return "True", {"IllusionBlack.IsUserDecoy": {"User": user, "Value": True}}
            return "False", {"IllusionBlack.IsUserDecoy": {"User": user, "Value": False}}
        return None

    def is_subdomain_decoy(self, subdomain):
        """
        Checks if the subdomain is an IllusionBLACK TI decoy
        Args:
            subdomain: The subdomain to check. For example: experience.illusionblack.com
        Returns: True if subdomain is a decoy else False
        """
        response = self._http_request(
            method="GET",
            url_suffix="/decoy/recon",
            ok_codes=(200,)
        )
        ti_decoys: list = response["items"]
        for ti_decoy in ti_decoys:
            if subdomain == ti_decoy["name"]:
                return "True", {"IllusionBlack.IsSubdomainDecoy": {"Subdomain": subdomain, "Value": True}}
            return "False", {"IllusionBlack.IsSubdomainDecoy": {"Subdomain": subdomain, "Value": False}}
        return None

    def get_events(self, limit=None, query=None, from_time=None, to_time=None):
        """
        Gets Events and corresponding Threat Parse data from IllusionBLACK based on the filtering parameters.
        Args:
            limit: Number of events to return per API call. Defaults to 10.
            query: IllusionBLACK orchestrate engine query string. Refer to IllusionBLACK doc for reference.
            from_time: ISO-8601 formatted datetime string of the starting time in the filter
            to_time: ISO-8601 formatted datetime string of the ending time in the filter
        Returns: A tuple with raw events and threat parse data corresponding to the events
        """
        raw_events, raw_threat_parse, offset = [], {}, 0    # type: ignore
        while True:
            response = self._http_request(
                method="GET",
                url_suffix="/events",
                params={"limit": limit, "expfilter": query, "from": from_time, "to": to_time, "offset": offset},
                ok_codes=(200,)
            )
            meta: dict = response["meta"]
            amount = meta["paging"]["amount"]

            raw_events.extend(response["events"])
            for tp in response.get("threat_parse", {}):
                tp_id = tp["id"]
                if tp_id not in raw_threat_parse:
                    tp.pop("id", None)
                    raw_threat_parse[tp_id] = tp

            offset += 1000
            if amount < 1000:
                break
        return raw_events, raw_threat_parse


def test_module(client):
    """
    Returning "ok" indicates that the integration works like it is supposed to. Connection to the service is successful.
    Args:
        client: IllusionBLACK client
    Returns:
        "ok" if test passed, anything else will fail the test.
    """
    try:
        message = client.ping()
        if message == "pong":
            return "ok"
    except DemistoException as e:
        if e.args[0] == "Error in API call [401] - Unauthorized":
            return_error("Failed to connect to IllusionBLACK. External API Token or Client Id might be invalid.")
        else:
            raise e


def convert_to_demisto_severity(ib_severity="medium", tp_score_based=False, score=0):
    """
    Converts the IllusionBLACK Threat Parse score for an attacker to demisto incident severity
    Args:
        ib_severity: IllusionBLACK severity. Some events do not have threat parse score.
        tp_score_based: If score is based on Threat Parse cumulative score
        score: The cumulative Threat Parse score
    Returns: The demisto incident severity ranging from 1 to 4
    """
    severity = 1
    if tp_score_based:
        severity = score // 25
        severity = 1 if severity < 1 else severity
        severity = 4 if severity > 4 else severity
    else:
        if ib_severity == "low":
            severity = 2
        elif ib_severity == "medium":
            severity = 3
        elif ib_severity == "high":
            severity = 4
    return severity


def process_events(events, threat_parse):
    """
    Converts raw events and raw threat parse to demisto incidents based on common parameters.
    Args:
        events: Raw events from IllusionBLACK
        threat_parse: Raw Threat Parse from IllusionBLACK
    Returns: A list of raw incidents with data pertinent to demisto incident format.
    """
    raw_incident_data: dict[str, Any] = {}

    for event in events:
        attacker_id = event.get("attacker.id", "")
        decoy_id = event.get("decoy.id", "")
        attack_type = event.get("type", "")
        ib_severity = event.get("severity")

        incident_id = "-".join(filter(None, [attacker_id, decoy_id, attack_type])).rstrip("-")
        title = f"{attack_type} activity by {attacker_id} on {decoy_id} decoy"
        tps = event.get("threat_parse_ids", [])

        score, is_tp = 0, False
        for tp in tps:
            is_tp = True
            score += threat_parse[tp]["score"]
        severity = convert_to_demisto_severity(ib_severity=ib_severity, tp_score_based=is_tp, score=score)
        raw_incident = raw_incident_data.setdefault(
            incident_id,
            {
                "events": [],
                "threat_parse_ids": [],
                "title": "",
                "severity": 1,
                "attack_type": "illusionblack_event",
                "attacker_id": "",
                "decoy_id": "",
                "source": "IllusionBLACK"
            }
        )
        raw_incident["events"].append(event["id"])
        raw_incident["threat_parse_ids"].extend(tps)
        raw_incident["threat_parse_ids"] = list(set(raw_incident["threat_parse_ids"]))
        raw_incident["title"] = title
        raw_incident["severity"] = severity
        raw_incident["attack_type"] = attack_type
        raw_incident["attacker_id"] = attacker_id
        raw_incident["decoy_id"] = decoy_id

    return raw_incident_data


def create_incident(raw_incident):
    """
    Creates a demisto incident from a raw incident.
    Args:
        raw_incident: The data in the raw incident processed from raw events and Threat Parse from IllusionBLACK
    Returns: Demisto incident dict
    """
    demisto.info(f"Severity is {raw_incident['severity']}")
    return {
        "name": raw_incident["title"],
        "severity": raw_incident["severity"],
        "rawJSON": json.dumps(raw_incident)
    }


def fetch_incidents(first_fetch, client):
    """
    Automated fetching of incidents from IllusionBLACK. For first run 2 days is the fixed duration for events.
    Args:
        first_fetch: For first fetch the timespan to consider to fetch incidents. Example: 2 days, 5 weeks etc
        client: IllusionBLACK client
    Returns: Demisto Incidents
    """
    now = datetime.now(tz=UTC)
    demisto.info(f"IllusionBLACK: Fetching incidents at {now}")
    demisto_last_run = demisto.getLastRun()
    if "last_run" in demisto_last_run:
        last_run = datetime.fromisoformat(demisto_last_run["last_run"])
    else:
        last_run, _ = parse_date_range(first_fetch)
        last_run = last_run.replace(tzinfo=UTC)
    if now - last_run < timedelta(minutes=5):
        return []
    from_time = last_run.replace(microsecond=0).isoformat()
    to_time = now.replace(microsecond=0).isoformat()
    demisto.debug(f"IllusionBLACK: Getting raw events from {from_time} to {to_time}")
    events, all_threat_parse = client.get_events(limit=1000, from_time=from_time, to_time=to_time)
    raw_incidents = process_events(events, all_threat_parse)
    incidents = []

    for _incident_id, raw_incident in raw_incidents.items():
        incidents.append(create_incident(raw_incident))
    demisto.setLastRun({"last_run": to_time})
    return incidents


def main():
    client_id = demisto.params().get("client_id")
    token = demisto.params().get("token")
    base_url = urljoin(demisto.params()["url"], "/apiv1")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    LOG(f"Command being called is {demisto.command()}")
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            client_id=client_id,
            token=token,
            proxy=proxy
        )

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == "illusionblack-get-ad-decoys":
            return_outputs(*client.get_ad_decoys())
        elif demisto.command() == "illusionblack-get-network-decoys":
            return_outputs(*client.get_network_decoys())
        elif demisto.command() == "illusionblack-get-ti-decoys":
            return_outputs(*client.get_ti_decoys())
        elif demisto.command() == "illusionblack-is-host-decoy":
            return_outputs(*client.is_host_decoy(demisto.args()["host"]))
        elif demisto.command() == "illusionblack-is-user-decoy":
            return_outputs(*client.is_user_decoy(demisto.args()["user"]))
        elif demisto.command() == "illusionblack-is-subdomain-decoy":
            return_outputs(*client.is_subdomain_decoy(demisto.args()["subdomain"]))
        elif demisto.command() == "illusionblack-get-events":
            args = demisto.args()
            events, _ = client.get_events(args.get("limit"), args.get("query"), args.get("from"), args.get("to"))
            return_outputs(
                tableToMarkdown("IllusionBLACK Events", events),
                {"IllusionBlack.Event(val.id==obj.id)": events},
                events
            )
        elif demisto.command() == "illusionblack-get-event-by-id":
            events, _ = client.get_events(query=f"id == \"{demisto.args()['id']}\"")
            if len(events) != 1:
                return_error("Invalid event ID")
            event = events[0]
            return_outputs(
                tableToMarkdown("IllusionBLACK Single Event", event),
                {"IllusionBlack.Event(val.id==obj.id)": event},
                event
            )
        elif demisto.command() == "fetch-incidents":
            demisto.incidents(fetch_incidents(demisto.params().get("first_fetch", "2 days"), client=client))

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "builtins"):
    main()
