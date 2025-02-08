import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """

import dataclasses
import collections
import functools
import itertools
import json
import math
import time
import typing
import urllib3

from collections.abc import Callable, Mapping, MutableMapping
from datetime import datetime, timedelta, UTC
from typing import Any, Generic, Literal, TypeAlias, TypeVar

import dateutil.parser

# Disable insecure warnings
urllib3.disable_warnings()

"""Helper function"""

FetchType: TypeAlias = Literal["Security Events", "Threats"]
AlertStatus: TypeAlias = Literal["ACTIVE", "CLOSED"]
Severity: TypeAlias = Literal["Low", "Medium", "High", "Critical"]

Fn: TypeAlias = Callable[..., Any]

Incident: TypeAlias = MutableMapping[str, Any]
SecurityEvent: TypeAlias = Incident
Threat: TypeAlias = Incident

XSOARIncident: TypeAlias = Mapping[str, Any]

IncidentId = TypeVar("IncidentId", str, int)

INTEGRATION_NAME = "Hurukai"

TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

SEVERITIES: tuple[str, ...] = typing.get_args(Severity)
DEFAULT_SEVERITY: str = SEVERITIES[0]

MAX_NUMBER_OF_ALERTS_PER_CALL = 25

HFL_SECURITY_EVENT_INCOMING_ARGS = ["status"]
HFL_THREAT_INCOMING_ARGS = [
    "status",
    "security_event_count_by_level.critical",
    "security_event_count_by_level.high",
    "security_event_count_by_level.medium",
    "security_event_count_by_level.low",
    "mitre_tactics",
    "agents.agent_hostname",
    "last_seen",
    "rules.rule_name",
    "top_agents.agent_hostname",
    "top_impacted_users.user_name",
    "top_rules.rule_name",
    "impacted_users.full_name",
    "note.content",
]

SECURITY_EVENT_STATUS = {
    "new",
    "probable_false_positive",
    "false_positive",
    "investigating",
    "closed",
}

STATUS_HFL_TO_XSOAR = {
    "new": "New",
    "probable_false_positive": "Closed",
    "false_positive": "Closed",
    "investigating": "In Progress",
    "closed": "Closed",
}

STATUS_XSOAR_TO_HFL = {
    "New": "new",
    "Reopened": "investigating",
    "In Progress": "investigating",
    "Closed": "closed",
}

HFL_THREAT_OUTGOING_ARGS = {
    "status": f"Updated threat status, one of {'/'.join(STATUS_HFL_TO_XSOAR.keys())}"
}

HFL_SECURITY_EVENT_OUTGOING_ARGS = {
    "status": f"Updated security event status, one of {'/'.join(STATUS_HFL_TO_XSOAR.keys())}"
}

MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}


class IncidentType:
    SECURITY_EVENT = "sec"
    THREAT = "thr"


def _construct_request_parameters(args: dict, keys: list, params={}):
    """A helper function to add the keys arguments to the dict parameters"""

    parameters = {}
    if params is not None:
        for p in params:
            parameters[p] = params[p]

    for arg_field, filter_field in keys:
        value = args.get(arg_field, None)
        if value is not None:
            parameters[filter_field] = value

    return parameters


def _construct_output(results: list, keys: list):
    """A helper function to converts all results to a dict list with only the keys arguments"""

    output = []

    for col in results:
        row = {}
        for label, data_keys in keys:
            value = col
            if isinstance(data_keys, list):
                for key in data_keys:
                    value = value.get(key, None)
                    if value is None:
                        break
            else:
                value = value.get(data_keys, None)

            row[label] = value
        output.append(row)

    return output


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


class Client(BaseClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _http_request(self, *args, **kwargs):
        if kwargs.get("method", None) == "GET" and len(kwargs.get("params", {})) > 0:
            params = kwargs.pop("params")
            suffix = kwargs.pop("url_suffix")
            suffix += "?{}".format("&".join([f"{k}={v}" for (k, v) in params.items()]))
            kwargs["url_suffix"] = suffix

        return super()._http_request(*args, **kwargs)

    def test_api(self):
        return self._http_request(method="GET", url_suffix="/api/version")

    def get_api_token(self):
        data = assign_params(is_expirable=True)

        return self._http_request(
            method="POST", url_suffix="/api/user/api_token/", json_data=data
        )

    def get_endpoint_info(self, agent_id=None):
        if agent_id:
            return self._http_request(
                method="GET",
                url_suffix=f"/api/data/endpoint/Agent/{agent_id}/",
            )
        return None

    def api_call(
        self, api_method="GET", api_endpoint="/api/version", params={}, json_data={}
    ):
        return self._http_request(
            method=api_method,
            url_suffix=api_endpoint,
            params=params,
            json_data=json_data,
        )

    def endpoint_search(self, hostname=None, offset=0, threat_id=None, fields=None):
        fields_str = None
        if fields:
            fields_str = ",".join(fields)
        data = assign_params(
            hostname=hostname,
            offset=offset,
            threat_id=threat_id,
            fields=fields_str,
            limit=10000,
        )

        return self._http_request(
            method="GET", url_suffix="/api/data/endpoint/Agent/", params=data
        )

    def user_search(self, threat_id=None, fields=None):
        fields_str = None
        if fields:
            fields_str = ",".join(fields)
        data = assign_params(
            offset=0, threat_id=threat_id, fields=fields_str, limit=10000
        )

        return self._http_request(
            method="GET",
            url_suffix="/api/data/host_properties/local_users/windows/",
            params=data,
        )

    def data_hash_search(self, filehash=None):
        data = {}
        if filehash:
            data["values"] = filehash
            data["type"] = "hash"

        return self._http_request(
            method="GET",
            url_suffix="/api/data/search/Search/explorer_with_list/",
            params=data,
        )

    def invest_running_process(self, filehash=None):
        data = {}
        if filehash:
            data["binaryinfo.binaryinfo.sha256"] = filehash

        return self._http_request(
            method="GET",
            url_suffix="/api/data/investigation/hunting/Process/",
            params=data,
        )

    def invest_runned_process(self, filehash=None):
        data = {}
        if filehash:
            data["hashes.sha256"] = filehash

        return self._http_request(
            method="GET", url_suffix="/api/data/telemetry/Processes/", params=data
        )

    def job_create(self, agent_id, action, parameters=None):
        data = {
            "targets": {"agents": [agent_id]},
            "actions": [
                {
                    "value": action,
                    "params": parameters or {},
                }
            ],
        }

        demisto.debug(str(data))

        return self._http_request(
            method="POST", url_suffix="/api/data/Job/", json_data=data
        )

    def jobinstance_list(self, data=None):
        kwargs = {
            "method": "GET",
            "url_suffix": "/api/data/JobInstance/",
        }

        if data is not None:
            kwargs["params"] = data

        return self._http_request(**kwargs)

    # EndPoint / Récupération de tous les processus d'une machine donnée avec le job fini
    def getProcess_list(self, job_id=None):
        url_suffix = f"/api/data/investigation/hunting/Process/?offset=0&job_id={job_id}&ordering=-name"

        return self._http_request(method="GET", url_suffix=url_suffix)

    def job_info(self, job_id):
        return self._http_request(
            method="GET",
            url_suffix=f"/api/data/Job/{job_id}",
        )

    def job_data(self, job_id, job_type, ordering=None):
        job_types = {
            "pipe": "/api/data/investigation/hunting/Pipe/",
            "driver": "/api/data/investigation/hunting/Driver/",
            "prefetch": "/api/data/investigation/hunting/Prefetch/",
            "scheduledtask": "/api/data/investigation/hunting/ScheduledTaskXML/",
            "runkey": "/api/data/investigation/hunting/RunKey/",
            "service": "/api/data/investigation/hunting/Service/",
            "process": "/api/data/investigation/hunting/Process/",
            "startup": "/api/data/investigation/hunting/Startup/",
            "persistence": "/api/data/investigation/hunting/PersistanceFile/",
            "wmi": "/api/data/investigation/hunting/Wmi/",
            "networkshare": "/api/data/investigation/hunting/NetworkShare/",
            "session": "/api/data/investigation/hunting/Session/",
            "artifact": "/api/data/investigation/artefact/Artefact/",
            "ioc": "/api/data/investigation/ioc/IOC/",
        }
        url_suffix = f"{job_types[job_type]}?limit=10000&job_id={job_id}"
        if ordering is not None:
            url_suffix += f"&ordering={ordering}"

        return self._http_request(method="GET", url_suffix=url_suffix)

    def telemetry_data(self, telemetry_type, params=None):
        telemetry_urls = {
            "processes": "/api/data/telemetry/Processes/",
            "binary": "/api/data/telemetry/Binary/",
            "network": "/api/data/telemetry/Network/",
            "eventlog": "/api/data/telemetry/FullEventLog/",
            "dns": "/api/data/telemetry/DNSResolution/",
            "windows_authentications": "/api/data/telemetry/authentication/AuthenticationWindows/",
            "linux_authentications": "/api/data/telemetry/authentication/AuthenticationLinux/",
            "macos_authentications": "/api/data/telemetry/authentication/AuthenticationMacos/",
        }

        kwargs = {
            "method": "GET",
            "url_suffix": telemetry_urls[telemetry_type],
        }

        if params is not None:
            kwargs["params"] = params

        return self._http_request(**kwargs)

    def isolate_endpoint(self, agentid):
        return self._http_request(
            method="POST",
            url_suffix=f"/api/data/endpoint/Agent/{agentid}/isolate/",
        )

    def get_process_graph(self, process_uuid):
        return self._http_request(
            method="GET",
            url_suffix=f"/api/data/telemetry/Processes/{process_uuid}/graph/",
        )

    def search_whitelist(self, keyword, provided_by_hlab):
        return self._http_request(
            method="GET",
            url_suffix=f"/api/data/threat_intelligence/WhitelistRule/?"
            f"offset=0&limit=100&search={keyword}&"
            f"ordering=-last_update&provided_by_hlab={provided_by_hlab}",
        )

    def add_whitelist(
        self, comment, sigma_rule_id, target, field, case_insensitive, operator, value
    ):
        data = {
            "comment": comment,
            "sigma_rule_id": sigma_rule_id,
            "target": target,
            "criteria": [
                {
                    "case_insensitive": case_insensitive,
                    "field": field,
                    "operator": operator,
                    "value": value,
                }
            ],
        }

        return self._http_request(
            method="POST",
            url_suffix="/api/data/threat_intelligence/WhitelistRule/",
            json_data=data,
        )

    def add_criterion_to_whitelist(self, id, field, case_insensitive, operator, value):
        data = self.get_whitelist(id)
        data["criteria"].append(
            {
                "case_insensitive": case_insensitive,
                "field": field,
                "operator": operator,
                "value": value,
            }
        )

        return self._http_request(
            method="PUT",
            url_suffix=f"/api/data/threat_intelligence/WhitelistRule/{id}/",
            json_data=data,
        )

    def get_whitelist(self, id):
        return self._http_request(
            method="GET",
            url_suffix=f"/api/data/threat_intelligence/WhitelistRule/{id}/",
        )

    def delete_whitelist(self, id):
        return self._http_request(
            method="DELETE",
            url_suffix=f"/api/data/threat_intelligence/WhitelistRule/{id}/",
            return_empty_response=True,
        )

    def deisolate_endpoint(self, agentid):
        return self._http_request(
            method="POST",
            url_suffix=f"/api/data/endpoint/Agent/{agentid}/deisolate/",
        )

    def change_security_event_status(self, eventid, status):
        data = {}  # type: Dict[str,Any]

        if isinstance(eventid, list):
            data["ids"] = eventid
        else:
            data["ids"] = [eventid]

        if status.lower() == "new":
            data["new_status"] = "new"
        elif status.lower() == "investigating":
            data["new_status"] = "investigating"
        elif status.lower() == "false positive":
            data["new_status"] = "false_positive"
        elif status.lower() == "closed":
            data["new_status"] = "closed"

        return self._http_request(
            method="POST", url_suffix="/api/data/alert/alert/Alert/tag/", json_data=data
        )

    def change_threat_status(self, threat_id, status):
        data = {}  # type: Dict[str,Any]

        if isinstance(threat_id, list):
            data["threat_ids"] = threat_id
        else:
            data["threat_ids"] = [threat_id]

        if status.lower() == "new":
            data["new_status"] = "new"
        elif status.lower() == "investigating":
            data["new_status"] = "investigating"
        elif status.lower() == "false positive":
            data["new_status"] = "false_positive"
        elif status.lower() == "closed":
            data["new_status"] = "closed"

        data["tag_security_events"] = True
        data["update_by_query"] = True

        return self._http_request(
            method="PATCH",
            url_suffix="/api/data/alert/alert/Threat/status/",
            json_data=data,
        )

    def update_threat_description(self, threat_id, content):
        threat = self._http_request(
            method="GET", url_suffix=f"/api/data/alert/alert/Threat/{threat_id}/"
        )

        # API doesn't return a JSON response when the note doesn't exist, but
        # rather an empty one...
        note: requests.Response = self._http_request(
            method="GET",
            url_suffix=f"/api/data/alert/alert/Threat/{threat_id}/note/",
            return_empty_response=True,
            empty_valid_codes=[200],
        )

        note_already_exist = bool(note.text)

        if note_already_exist:
            method = "PATCH"
        else:
            method = "POST"

        return self._http_request(
            method=method,
            url_suffix=f"/api/data/alert/alert/Threat/{threat_id}/note/",
            json_data={"title": threat["slug"], "content": content},
        )

    def list_policies(self, policy_name=None):
        data = {}

        if policy_name:
            data["search"] = policy_name

        return self._http_request(
            method="GET", url_suffix="/api/data/endpoint/Policy/", params=data
        )

    def list_sources(self, source_type="ioc", source_name=None):
        data = {}

        if source_name:
            data["search"] = source_name

        if source_type == "yara":
            url_suffix = "/api/data/threat_intelligence/YaraSource/"
        elif source_type == "sigma":
            url_suffix = "/api/data/threat_intelligence/SigmaSource/"
        elif source_type == "ioc":
            url_suffix = "/api/data/threat_intelligence/IOCSource/"
        else:
            url_suffix = ""

        return self._http_request(method="GET", url_suffix=url_suffix, params=data)

    def search_ioc(self, ioc_value, source_id):
        data = {"source_id": source_id, "search": ioc_value}

        return self._http_request(
            method="GET",
            url_suffix="/api/data/threat_intelligence/IOCRule/",
            params=data,
        )

    def add_ioc_to_source(
        self, ioc_value, ioc_type, ioc_comment, ioc_status, source_id
    ):
        testing_status = None

        if ioc_status == "testing":
            testing_status = "in_progress"

        data = {
            "type": ioc_type,
            "value": ioc_value,
            "comment": ioc_comment,
            "source_id": source_id,
            "hl_status": ioc_status,
            "hl_local_testing_status": testing_status,
        }

        return self._http_request(
            method="POST",
            url_suffix="/api/data/threat_intelligence/IOCRule/",
            json_data=data,
        )

    def delete_ioc(self, ioc_id):
        return self._http_request(
            method="DELETE",
            url_suffix=f"/api/data/threat_intelligence/IOCRule/{ioc_id}/",
            return_empty_response=True,
        )

    def assign_policy_to_agent(self, policyid, agentid):
        data = {"agent_ids": [agentid]}

        return self._http_request(
            method="POST",
            url_suffix=f"/api/data/endpoint/Policy/{policyid}/add_agents/",
            json_data=data,
        )


def assign_policy_to_agent(client, args):
    context = {}
    policy_name = args.get("policy", None)

    results = client.list_policies(policy_name)
    policyid = None
    for policy in results["results"]:
        if args["policy"] == policy["name"]:
            policyid = policy["id"]
            break
    if policyid:
        client.assign_policy_to_agent(policyid, args["agentid"])
        context["Message"] = (
            f"Policy {policy_name} successfully assigned to agent {args['agentid']}"
        )
    else:
        context["Message"] = f"Unknown policy {policy_name}"

    return CommandResults(readable_output=context["Message"], outputs=context)


def test_module(client: Client, *args: Any, **kwargs: Any) -> str:
    return "ok" if "version" in client.test_api() else "nope"


@dataclasses.dataclass(kw_only=True)
class FetchHistory(Generic[IncidentId]):

    last_fetch: Optional[int] = None
    already_fetched: list[IncidentId] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(kw_only=True, frozen=True)
class LastRun:

    security_event: FetchHistory
    threat: FetchHistory

    def as_dict(self) -> dict[str, dict[str, Any]]:
        return dataclasses.asdict(self)


def get_last_run() -> LastRun:
    """Simple wrapper around the 'demisto.getLastRun()' to convert dictionary
    returned by 'demisto.getLastRun()' to a LastRun object.

    Also handle old format that contain only data for alerts/security events.

    Returns:
        A LastRun object.
    """

    stored_last_run: dict[str, Any] = demisto.getLastRun()
    last_run: dict[str, dict[str, Any]]

    if stored_last_run:
        # check for the old format that don't have the "threat" support (<1.2.0)
        if "last_fetch" in stored_last_run:
            last_run = {
                "security_event": stored_last_run,
                "threat": {},
            }
        else:
            last_run = stored_last_run  # already have the correct format
    else:
        last_run = {
            "security_event": {},
            "threat": {},
        }

    for history in last_run.values():
        # Check the use of the old timestamp format and convert it.
        # It was multiplied by 1_000_000 for real reason except for keeping
        # microsecond, which has no benefit.
        try:
            datetime.fromtimestamp(history["last_fetch"])
        except (KeyError, TypeError):
            # last_fetch is not (yet) present in history or was 'None'
            pass
        except ValueError:
            # last_fetch's year is out of range (year > 50_000_000)
            history["last_fetch"] = history["last_fetch"] // 1_000_000

    return LastRun(
        security_event=FetchHistory(**last_run["security_event"]),
        threat=FetchHistory(**last_run["threat"]),
    )


def _adjust_max_fetch_value(max_fetch: int, already_fetched_count: int) -> int:
    """Adjust the max_fetch value from how many incidents have been already fetched."""
    if max_fetch <= already_fetched_count:
        raise RuntimeError(
            f"Too many incidents have been already fetched: Get {max_fetch=}, "
            f"but {already_fetched_count} incidents have been already fetched "
            f"(that probably mean there are semantic errors in the code)"
        )

    return max_fetch - already_fetched_count


def _get_fetching_cursor(fetch_history: FetchHistory) -> datetime:

    if not isinstance(fetch_history.last_fetch, int | float):
        raise ValueError(
            f"Expected an integer value for 'fetch_history.last_fetch', "
            f"get '{fetch_history.last_fetch}'"
        )

    return datetime.fromtimestamp(
        # minus 1sec to overlap with previous fetch and ensure to miss nothing
        fetch_history.last_fetch - 1,
        tz=UTC,
    )


def _incident_should_be_fetched(
    incident_type: Literal["security event", "threat"],
    incident_id: IncidentId,
    incident_timestamp: int,
    fetched: list[IncidentId],
    fetched_from_last_fetch: list[IncidentId],
    fetching_cursor: datetime,
) -> bool:
    """Check if an incident should be sent to the XSOAR instance or not.

    Args:
        incident_type: Type of the incident: "security event" or "threat".
        incident_id: ID of the incident. A string for security events, integer
          for threats.
        incident_timestamp: Creation timestamp of the incident, will be compared
          with the 'fetching_cursor'.
        fetched: List of already fetched ID for the current fetching process.
        fetched_from_last_fetch: List of already fetched ID from previous
          fetching processes.
        fetching_cursor: Timestamp used for querying the remote HarfangLab EDR
          API instance.

    Returns:
        True: The incident should be sent to the XSOAR instance.
        False: The incident shouldn't send to the XSOAR instance. Also, that
          probably mean there are some semantic error in the code.
    """

    # Skip incidents that has been already fetched in the current fetch.
    # In fact, that should never happen and this statement can be replaced
    # by a simple raise error.
    if incident_id in fetched:
        demisto.error(
            f"'{incident_id}' was already fetched from current fetch: "
            f"this {incident_type} shouldn't have been present twice in the "
            f"same fetching processing"
        )
        return False

    # Skip incidents that has been fetched in previous fetch.
    # In fact, that should never happen and this statement can be replaced
    # by a simple raise error.
    if incident_id in fetched_from_last_fetch:
        demisto.error(
            f"'{incident_id}' was already fetched from a previous fetch: "
            f"this {incident_type} shouldn't have been re-fetched"
        )
        return False

    # Skip incidents that are prior to the given timestamp.
    # In fact, that should never happen and this statement can be replaced
    # by a simple raise error.
    # note: time in remote instance are stored in UTC
    if incident_timestamp < fetching_cursor.timestamp():
        demisto.error(
            f"'{incident_id}' has been created before the given timestamp: "
            f"expected only {incident_type}s created after {fetching_cursor}, "
            f"get one created at "
            f"{datetime.fromtimestamp(incident_timestamp, tz=UTC)}"
        )
        return False

    return True


def _generate_xsoar_incident(
    incident: Incident,  # some additional data will be added
    incident_name: str,
    incident_type: Literal["alert", "threat"],  # <!> use 'alert', not 'security event'
    incident_id: str | int,
    incident_severity: Severity,
    incident_time: str,
    mirror_instance: str,
    mirror_direction: str | None,
    integration_base_url: str,
) -> XSOARIncident:
    """Create an XSOAR compatible incident object.

    Args:
        incident: The actual incident object, the on fetch from remote EDR instance.
        incident_name: Name of the incident.
        incident_type: Type of the incident: "alert" (for security-event) or "threat".
        incident_id: ID of the incident. A string for security events, integer
          for threats.
        incident_severity: Severity of the incident.
        incident_time: ISO representation of the timestamps when the incident
          occurred.
        mirror_instance: Name of the mirrored instance.
        mirror_direction: Mirrored direction for action. Can be "In", "Out",
          "Both" or None (see 'MIRROR_DIRECTION_MAPPING' values).
        integration_base_url: Base URL of the remote EDR instance, set in the
          configuration of the connector.

    Returns:
        An XSOAR compatible incident object.
    """

    # note: 'alert' is the legacy name for 'security event'
    # for retro-compatibility purpose, the name 'alert' is still used here,
    # but in the end, should be replaced by 'security event'

    additional_data: dict[str, Any] = {}

    match incident_type:
        case "alert":
            additional_data["incident_type"] = f"{INTEGRATION_NAME} alert"
            additional_data["incident_link"] = (
                f"{integration_base_url}/security-event/{incident_id}/summary"
            )
        case "threat":
            additional_data["incident_type"] = f"{INTEGRATION_NAME} threat"
            additional_data["incident_link"] = (
                f"{integration_base_url}/threat/{incident_id}/summary"
            )
        case _:
            raise ValueError(
                f"Invalid value for 'incident_type' argument: "
                f"expected 'alert' or 'threat', get '{incident_type}'"
            )

    additional_data["mirror_instance"] = mirror_instance
    additional_data["mirror_direction"] = mirror_direction

    # what is that? that was present in the old threat implementation
    # threat["mirror_tags"] = ["comments", "work_notes"]

    incident.update(additional_data)

    occurred: str = incident_time
    severity: int = SEVERITIES.index(incident_severity) + 1
    json_dump: str = json.dumps(incident, ensure_ascii=True)

    return {
        "name": incident_name,
        "occurred": occurred,
        "severity": severity,
        "rawJSON": json_dump,
    }


def _fetch_security_event_incidents(
    client: Client,
    *,
    fetch_history: FetchHistory,
    minimum_severity_to_fetch: Severity,
    max_fetch: int,
    first_fetch_timestamp: int,
    mirror_instance: str,
    mirror_direction: str | None,  # None is a valid value
    alert_type: Optional[list[str]],
    alert_status: Optional[list[str]],
    incidents: list[XSOARIncident],
) -> None:
    """Wrapper for fetching security events on remote HarfangLab EDR instance.

    Args:
        client: Demisto client to use. Initialized in the 'main' function.
        fetch_history: Fetch history object for security events.
        minimum_severity_to_fetch: Minimum level to fetch. Can be "Low",
          "Medium", "High" or "Critical" (see 'Severity' type).
        max_fetch: Maximum count of security event to fetch per call of this
          function (will be adjusted).
        first_fetch_timestamp: Timestamp to use on first fetch.
        mirror_instance: Name of the mirrored instance.
        mirror_direction: In which direction action should be mirrored. Can be
          "In", "Out", "Both" or None (see 'MIRROR_DIRECTION_MAPPING' values).
        alert_type: Security event type that should be fetched. Comma separated
          string/list (eg.: "sigma,yara,vt").
        alert_status: Security event status that should be fetched. Can be
          ["new", "probable_false_positive", "investigating"] for "ACTIVE" status,
          ["closed", "false_positive"] for "CLOSED" status,
          or None.
        incidents: List to use for append the fetched security events.

    Raises:
        ValueError: Can occur both in case of invalid user/configuration data
          or invalid/unexpected data type on fetched security events.
        KeyError: Can occur if there are missing keys in the fetched security
          events.

        In both case, those errors are not expected and should be reported.

    Returns:
        Nothing, the 'incidents' list is updated.
    """

    fetched: list[str] = []
    fetched_from_last_fetch: list[str] = []

    if fetch_history.last_fetch:
        fetched_from_last_fetch.extend(fetch_history.already_fetched)
    else:
        fetch_history.last_fetch = first_fetch_timestamp

    max_fetch = _adjust_max_fetch_value(max_fetch, len(incidents))
    exclude_fetched_from_last_fetch_filter = {}

    if fetched_from_last_fetch:
        # exclude every security events that has been already fetched
        exclude_fetched_from_last_fetch_filter["id__exact!"] = ",".join(
            fetched_from_last_fetch
        )

    fetching_cursor: datetime = _get_fetching_cursor(fetch_history)

    demisto.info(
        f"Fetch security events created after {fetching_cursor}... (max. {max_fetch})"
    )

    security_events: list[SecurityEvent] = get_security_events(
        client=client,
        min_created_timestamp=fetching_cursor.strftime("%Y-%m-%dT%H:%M:%SZ"),
        alert_status=alert_status,
        alert_type=alert_type,
        min_severity=minimum_severity_to_fetch,
        max_fetch=max_fetch,
        extra_filters={
            **exclude_fetched_from_last_fetch_filter,
        },
    )

    demisto.info(
        f"{len(security_events)} security events fetched from {mirror_instance}"
    )

    security_event: SecurityEvent

    # fetched security events are expected to be already sorted by time creation,
    # but better be safe
    for security_event in sorted(security_events, key=lambda d: d["alert_time"]):

        security_event_id: str = security_event["id"]  # id should be always present

        security_event_creation_timestamp: int = math.floor(
            dateutil.parser.isoparse(security_event["alert_time"]).timestamp()
        )

        if not _incident_should_be_fetched(
            incident_type="security event",
            incident_id=security_event_id,
            incident_timestamp=security_event_creation_timestamp,
            fetched=fetched,
            fetched_from_last_fetch=fetched_from_last_fetch,
            fetching_cursor=fetching_cursor,
        ):
            continue

        incident: XSOARIncident = _generate_xsoar_incident(
            incident=security_event,
            incident_name=security_event["rule_name"],
            incident_type="alert",
            incident_id=security_event_id,
            incident_severity=security_event["level"].capitalize(),
            incident_time=security_event["alert_time"],
            mirror_instance=mirror_instance,
            mirror_direction=mirror_direction,
            integration_base_url=client._base_url,
        )

        incidents.append(incident)
        fetched.append(security_event_id)

        fetch_history.last_fetch = max(
            (fetch_history.last_fetch, security_event_creation_timestamp)
        )

        if len(incidents) >= max_fetch:
            break

    if fetched:

        demisto.info(
            f"{len(fetched)}/{len(security_events)} new security events send to XSOAR"
        )

        if fetch_history.last_fetch > fetching_cursor.timestamp() + 1:
            # Only clear previously fetched security events if the last_fetch
            # timestamp have changed.
            # Otherwise, that can conduct to a deadlock if there are more
            # than 'max_fetch' security events that are generated in less
            # than 1 second.
            fetch_history.already_fetched.clear()

        fetch_history.already_fetched.extend(fetched)


def _fetch_threat_incidents(
    client: Client,
    *,
    fetch_history: FetchHistory,
    minimum_severity_to_fetch: Severity,
    max_fetch: int,
    first_fetch_timestamp: int,
    mirror_instance: str,
    mirror_direction: str | None,  # None is a valid value
    threat_status: Optional[list[str]],
    incidents: list[XSOARIncident],
) -> None:
    """Wrapper for fetching threats on remote HarfangLab EDR instance.

    Args:
        client: Demisto client to use. Initialized in the 'main' function.
        fetch_history: Fetch history object for threats.
        minimum_severity_to_fetch: Minimum level to fetch. Can be "Low",
          "Medium", "High" or "Critical" (see 'Severity' type).
        max_fetch: Maximum count of threat to fetch per call of this
          function (will be adjusted).
        first_fetch_timestamp: Timestamp to use on first fetch.
        mirror_instance: Name of the mirrored instance.
        mirror_direction: In which direction action should be mirrored. Can be
          "In", "Out", "Both" or None (see 'MIRROR_DIRECTION_MAPPING' values).
        threat_status: Threat status that should be fetched. Can be
          ["new", "probable_false_positive", "investigating"] for "ACTIVE" status,
          ["closed", "false_positive"] for "CLOSED" status,
          or None.
        incidents: List to use for append the fetched threats.

    Raises:
        ValueError: Can occur both in case of invalid user/configuration data
          or invalid/unexpected data type on fetched security events.
        KeyError: Can occur if there are missing keys in the fetched security
          events.

        In both case, those errors are not expected and should be reported.

    Returns:
        Nothing, the 'incidents' list is updated.
    """

    fetched: list[int] = []
    fetched_from_last_fetch: list[int] = []

    if fetch_history.last_fetch:
        fetched_from_last_fetch.extend(fetch_history.already_fetched)
    else:
        fetch_history.last_fetch = first_fetch_timestamp

    max_fetch = _adjust_max_fetch_value(max_fetch, len(incidents))

    # exclude every threats that has been already fetched
    exclude_fetched_from_last_fetch_filter = {
        # On first fetch, use 0 as floor id - threat's id should always start at 1.
        "id__gt": max(fetched_from_last_fetch or [0]),
        # Order by 'creation_date' rather than 'last_seen' to avoid to fetch
        # continuously over the same triggered threats.
        # Also, 'creation_date' will be closer to sequential id rather
        # than 'first_seen'.
        "ordering": "creation_date",
    }

    fetching_cursor: datetime = _get_fetching_cursor(fetch_history)

    demisto.info(f"Fetch threats created after {fetching_cursor}... (max. {max_fetch})")

    threats: list[Threat] = get_threats(
        client=client,
        min_created_timestamp=fetching_cursor.strftime("%Y-%m-%dT%H:%M:%SZ"),
        threat_status=threat_status,
        min_severity=minimum_severity_to_fetch,
        max_fetch=max_fetch,
        extra_filters={
            **exclude_fetched_from_last_fetch_filter,
        },
    )

    demisto.info(f"{len(threats)} threats fetched from {mirror_instance}")

    threat: Threat

    # fetched threats are expected to be already sorted by time creation,
    # but better be safe
    for threat in sorted(threats, key=lambda d: d["creation_date"]):

        threat_id: int = threat["id"]  # id should be always present

        threat_creation_timestamp: int = math.floor(
            dateutil.parser.isoparse(threat["creation_date"]).timestamp()
        )

        if not _incident_should_be_fetched(
            incident_type="threat",
            incident_id=threat_id,
            incident_timestamp=threat_creation_timestamp,
            fetched=fetched,
            fetched_from_last_fetch=fetched_from_last_fetch,
            fetching_cursor=fetching_cursor,
        ):
            continue

        incident: XSOARIncident = _generate_xsoar_incident(
            incident=threat,
            incident_name=threat["slug"],
            incident_type="threat",
            incident_id=threat_id,
            incident_severity=threat["level"].capitalize(),
            incident_time=threat["first_seen"],
            mirror_instance=mirror_instance,
            mirror_direction=mirror_direction,
            integration_base_url=client._base_url,
        )

        incidents.append(incident)
        fetched.append(threat_id)

        fetch_history.last_fetch = max(
            (fetch_history.last_fetch, threat_creation_timestamp)
        )

        if len(incidents) >= max_fetch:
            break

    if sorted(fetched) != fetched:
        demisto.debug("There is something wrong in threats fetching order")

    if fetched:

        demisto.info(f"{len(fetched)}/{len(threats)} new threats send to XSOAR")

        if fetch_history.last_fetch > fetching_cursor.timestamp() + 1:
            # Only clear previously fetched threats if the last_fetch
            # timestamp have changed.
            # Otherwise, that can conduct to a deadlock if there are more
            # than 'max_fetch' threats that are generated in less
            # than 1 second.
            fetch_history.already_fetched.clear()

        fetch_history.already_fetched.extend(fetched)


def fetch_incidents(
    client: Client, args: dict[str, Any]
) -> tuple[dict, list[XSOARIncident]]:
    """Fetch incident from remote EDR to XSOAR.

    incident = security event, threat or both (see 'FetchType' for valid values)

    Args:
        client: Demisto client to use. Initialized in the 'main' function.
        args:
            fetch_types: which type of incident to fetch.
            last_run: LastRun object - determine when the last fetch has been
              occurred, both for security event and threat.
            min_severity: Minimum level of incident to fetch. Can be "Low",
              "Medium", "High" or "Critical" (see 'Severity' type).
            mirror_direction: In which direction action should be mirrored. Can
              "None", "Incoming", "Outgoing", "Incoming And Outgoing" (see
              'MIRROR_DIRECTION_MAPPING' keys).
            alert_status: Incident status that should be fetched. Can be
              "ACTIVE", "CLOSED" or None.
            alert_type: Incident type that should be fetched. Comma separated
              string/list (eg.: "sigma,yara,vt") - only available for security
              event.
            first_fetch: How many past days should be fetched on run.
            max_fetch: Maximum count of incident to fetch per call of this
              function.

    Raises:
        KeyError: if 'fetch_types' or 'last_run' are missing from input 'args'.
        ValueError: if there are invalid/unexpected value/type in input 'args'.

    Returns:
        A LastRun object as dictionary and the list of new incidents to add
        to the XSOAR instance.
    """

    # * mandatory:
    fetch_types: list[FetchType] = args["fetch_types"]
    last_run: LastRun = args["last_run"]

    # * mandatory (w/ default):
    min_severity: Severity = args.get("min_severity", DEFAULT_SEVERITY)
    mirror_direction: str = args.get("mirror_direction", "None")

    # * optional:
    alert_status: Optional[AlertStatus] = args.get("alert_status")
    alert_type: Optional[list[str]] = args.get("alert_type")
    first_fetch: Optional[int | str] = args.get("first_fetch")
    max_fetch: Optional[int | str] = args.get("max_fetch")

    # need to be explicitly convert to int
    # default value is hardcoded (check the value in 'Hurukai.yml' definition)
    # zero will be automatically converted to the default value
    max_fetch = int(max_fetch or 200)

    mirror_instance: str = demisto.integrationInstance()

    # check if 'fetch_types' as been set (as it's a mandatory argument)
    if not fetch_types:
        raise ValueError("Missing value for 'fetch_types' argument")

    # check if values present in 'fetch_types' are valid
    for value in fetch_types:
        if value not in typing.get_args(FetchType):
            raise ValueError(
                f"Invalid value for 'fetch_types' argument: "
                f"expected one of {typing.get_args(FetchType)}, get '{value}'"
            )

    if min_severity not in SEVERITIES:
        raise ValueError(
            f"Invalid value for 'min_severity' argument: "
            f"expected one of {SEVERITIES}, get '{min_severity}'"
        )

    if mirror_direction not in MIRROR_DIRECTION_MAPPING:
        raise ValueError(
            f"Invalid value for 'mirror_direction' argument: "
            f"expected one of {tuple(MIRROR_DIRECTION_MAPPING)}, get '{mirror_direction}'"
        )

    if alert_status and alert_status not in typing.get_args(AlertStatus):
        raise ValueError(
            f"Invalid value for 'alert_status' argument: "
            f"expected one of {typing.get_args(AlertStatus)}, get '{alert_status}'"
        )

    if max_fetch <= 0:
        raise ValueError(
            f"Invalid value for 'max_fetch' argument: "
            f"expected a strict positive integer, get '{max_fetch}'"
        )

    # how many past days should be fetched (on first fetch only)
    past_days_to_fetch = int(first_fetch or 0)
    past_days_to_fetch_timestamp: int = math.floor(
        (utcnow() - timedelta(days=past_days_to_fetch)).timestamp()
    )

    # incident's status to fetch
    status_to_fetch: list[str] | None

    match alert_status:  # 'alert_status' can be renamed 'incident_status'
        case "ACTIVE":
            status_to_fetch = ["new", "probable_false_positive", "investigating"]
        case "CLOSED":
            status_to_fetch = ["closed", "false_positive"]
        case None:
            status_to_fetch = None
        case _:
            # unreachable code - only here for semantic purpose
            raise ValueError(
                f"Invalid value for 'alert_status': "
                f"expected 'ACTIVE', 'CLOSED' or None, get '{alert_status}'"
            )

    incidents: list[XSOARIncident] = []

    if "Security Events" in fetch_types:
        _fetch_security_event_incidents(
            client=client,
            fetch_history=last_run.security_event,
            minimum_severity_to_fetch=min_severity,
            max_fetch=max_fetch,
            first_fetch_timestamp=past_days_to_fetch_timestamp,
            mirror_instance=mirror_instance,
            mirror_direction=MIRROR_DIRECTION_MAPPING[mirror_direction],
            alert_type=alert_type,
            alert_status=status_to_fetch,
            incidents=incidents,  # the list will mutate (list.append(...))
        )

    # fetch threats only if every security events has been fetched first
    if len(incidents) < max_fetch and "Threats" in fetch_types:
        _fetch_threat_incidents(
            client=client,
            fetch_history=last_run.threat,
            minimum_severity_to_fetch=min_severity,
            max_fetch=max_fetch,
            first_fetch_timestamp=past_days_to_fetch_timestamp,
            mirror_instance=mirror_instance,
            mirror_direction=MIRROR_DIRECTION_MAPPING[mirror_direction],
            threat_status=status_to_fetch,
            incidents=incidents,  # the list will mutate (list.append(...))
        )

    return last_run.as_dict(), incidents


def get_endpoint_info(client, args):
    agent_id = args.get("agent_id", None)

    agent = client.get_endpoint_info(agent_id)

    readable_output = tableToMarkdown(
        f"Endpoint information for agent_id : {agent_id}", agent, removeNull=True
    )

    outputs = {"Harfanglab.Agent(val.agentid == obj.agentid)": agent}

    return_outputs(readable_output, outputs, agent)
    return agent


def api_call(client, args):
    api_method = args.get("api_method", "GET").upper()
    api_endpoint = args.get("api_endpoint", "/api/version")
    params = args.get("parameters", None)
    json_data = args.get("data")
    if json_data:
        json_data = json.loads(json_data)

    parameters = {}
    if params:
        tokens = params.split("&")
        for tok in tokens:
            res = tok.split("=")
            if len(res) == 2:
                parameters[res[0]] = urllib.parse.quote_plus(res[1])

    result = client.api_call(api_method, api_endpoint, parameters, json_data)

    return CommandResults(outputs_prefix="Harfanglab.API", outputs=result)


def endpoint_search(client, args):
    hostname = args.get("hostname", None)

    data = client.endpoint_search(hostname)

    readable_output = tableToMarkdown(
        f"Endpoint information for Hostname : {hostname}",
        data["results"],
        removeNull=True,
    )

    outputs = {"Harfanglab.Agent(val.agentid == obj.agentid)": data["results"]}

    return_outputs(readable_output, outputs, data)
    return data


def get_frequent_users(client: Client, args: dict[str, Any]) -> CommandResults:

    authentications: collections.Counter[tuple[str, str]] = collections.Counter()
    output = []

    # replace 0 with the default value
    # default value is already hardcoded into the .yml config
    limit = int(args.get("limit", 0)) or 3

    for system, class_name in (
        ("windows", "TelemetryWindowsAuthentication"),
        ("linux", "TelemetryLinuxAuthentication"),
        ("macos", "TelemetryMacosAuthentication"),
    ):

        obj = globals()[class_name]()

        if system == "windows":
            data = obj.get_telemetry(client, {"logon_type": 2, **args})
        else:
            data = obj.get_telemetry(client, args)

        for auth in data["results"]:
            authentications.update(
                [(system, auth["target_username"])],
            )

    for (system, username), auth_count in authentications.most_common():
        output.append(
            {
                "Username": username,
                "System": system,
                "Authentication attempts": auth_count,
            }
        )
        if len(output) >= limit:
            break

    readable_output = tableToMarkdown(
        f"Top {limit} authentications",
        output,
        headers=["Username", "System", "Authentication attempts"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Authentications.Users",
        outputs=output,
    )


def job_create(client, args, parameters=None, can_use_previous_job=True):
    action = args.get("action", None)
    agent_id = args.get("agent_id", None)

    if action is None or agent_id is None:
        return False, None

    if can_use_previous_job:
        previous_job_id = find_previous_job(client, action, agent_id)
        if previous_job_id is not None:
            return True, previous_job_id

    data = client.job_create(agent_id, action, parameters)

    job_id = data[0]["id"]
    return True, job_id


"""
    Returns a job status (context dict)
"""


def get_job_status(client, job_id):
    info = client.job_info(job_id)

    status = "running"

    if info["instance"] == info["done"]:
        status = "finished"
    elif info["error"] > 0:
        status = "error"
    elif info["canceled"] > 0:
        status = "canceled"
    elif info["waiting"] > 0:
        status = "waiting"
    elif info["running"] > 0:
        status = "running"
    elif info["injecting"] > 0:
        status = "injecting"

    # Creation time formating
    time_info = info["creationtime"].split(".")
    time_info = time_info[0].replace("T", " ").replace("Z", " ")

    context = {"ID": job_id, "Status": status, "Creation date": time_info}
    return context


def job_info(client, args):
    # ret vals : starting, running, finished
    job_ids = argToList(str(args.get("ids", None)))

    context = []
    for job_id in job_ids:
        context.append(get_job_status(client, job_id))

    readable_output = tableToMarkdown(
        "Jobs Info", context, headers=["ID", "Status", "Creation date"], removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Job.Info",
        outputs_key_field="ID",
        outputs=context,
    )


def find_previous_job(client, action, agent_id):
    starttime = (datetime.now(UTC) - timedelta(minutes=5)).strftime(
        "%Y-%m-%d %H:%M"
    )
    args = {
        "agent_id": agent_id,
        "action": action,
        "state": 2,
        "ordering": "-starttime",
        "starttime__gte": starttime,
    }
    data = client.jobinstance_list(args)
    job_id = None
    if data["count"] > 0:
        job_id = data["results"][0]["job_id"]

    return job_id


def common_result():
    # temporary, data need to reach ES
    time.sleep(10)


def common_job(job_id, job_type):
    context = {"ID": job_id, "Action": job_type}

    return CommandResults(
        readable_output=f"Job {job_id} started",
        outputs_prefix="Harfanglab.Job",
        outputs_key_field="ID",
        outputs=context,
    )


def job_pipelist(client, args):
    args["action"] = "getPipeList"
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_pipelist(client, args):
    job_id = args.get("job_id", None)

    common_result()

    data = client.job_data(job_id, "pipe", ordering="name")
    pipes = [x["name"] for x in data["results"]]
    readable_output = tableToMarkdown(
        "Pipe List", pipes, headers=["name"], removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Pipe",
        outputs_key_field="name",
        outputs=pipes,
    )


def job_prefetchlist(client, args):
    args["action"] = "getPrefetch"
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_prefetchlist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "prefetch", ordering="-last_executed")
    prefetchs = []
    for x in data["results"]:
        executable_name = x["executable_name"]
        last_executed = ""
        if len(x["last_executed"]) > 0:
            last_executed = x["last_executed"][0]
        prefetchs.append(
            {"executable name": executable_name, "last executed": last_executed}
        )

    readable_output = tableToMarkdown(
        "Prefetch List",
        prefetchs,
        headers=["executable name", "last executed"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Prefetch",
        outputs_key_field="name",
        outputs=prefetchs,
    )


def job_runkeylist(client, args):
    args["action"] = "getHives"
    parameters = {"bSystemHives": True, "bUsersHives": True, "bWantSlowPlugins": False}
    ret, job_id = job_create(client, args, parameters)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_runkeylist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "runkey", ordering="-last_executed")
    output = []
    for x in data["results"]:
        output.append(
            {
                "name": x["name"],
                "fullpath": x.get("binaryinfo", {}).get("fullpath", ""),
                "signed": x.get("binaryinfo", {})
                .get("binaryinfo", {})
                .get("signed", False),
                "md5": x.get("binaryinfo", {}).get("binaryinfo", {}).get("md5", ""),
            }
        )

    readable_output = tableToMarkdown(
        "RunKey List",
        output,
        headers=["name", "fullpath", "signed", "md5"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.RunKey",
        outputs_key_field="name",
        outputs=output,
    )


def job_scheduledtasklist(client, args):
    args["action"] = "getScheduledTasks"
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_scheduledtasklist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "scheduledtask", ordering="short_name")
    output = []
    for x in data["results"]:
        output.append(
            {
                "name": x["short_name"],
                "fullpath": x.get("binaryinfo", {}).get("fullpath", ""),
                "signed": x.get("binaryinfo", {})
                .get("binaryinfo", {})
                .get("signed", False),
                "md5": x.get("binaryinfo", {}).get("binaryinfo", {}).get("md5"),
            }
        )

    readable_output = tableToMarkdown(
        "Scheduled Task List",
        output,
        headers=["name", "fullpath", "signed", "md5"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.ScheduledTask",
        outputs_key_field="name",
        outputs=output,
    )


def job_linux_persistence_list(client, args):
    args["action"] = "persistanceScanner"
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_linux_persistence_list(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "persistence", ordering="short_name")
    output = []
    for x in data["results"]:
        output.append(
            {
                "type": x.get("persistance_type", None),
                "filename": x.get("binaryinfo", {}).get("filename", None),
                "fullpath": x.get("binaryinfo", {}).get("fullpath", None),
            }
        )

    readable_output = tableToMarkdown(
        "Linux persistence list",
        output,
        headers=["type", "filename", "fullpath"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Persistence",
        outputs_key_field="filename",
        outputs=output,
    )


def job_driverlist(client, args):
    args["action"] = "getLoadedDriverList"
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_driverlist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "driver", ordering="short_name")
    output = []
    for x in data["results"]:
        output.append(
            {
                "fullpath": x.get("binaryinfo", {}).get("fullpath", ""),
                "signed": x.get("binaryinfo", {})
                .get("binaryinfo", {})
                .get("signed", False),
                "md5": x.get("binaryinfo", {}).get("binaryinfo", {}).get("md5"),
            }
        )

    readable_output = tableToMarkdown(
        "Driver List", output, headers=["fullpath", "signed", "md5"], removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Driver",
        outputs_key_field="md5",
        outputs=output,
    )


def job_servicelist(client, args):
    args["action"] = "getHives"
    parameters = {"bSystemHives": True, "bUsersHives": True, "bWantSlowPlugins": False}
    ret, job_id = job_create(client, args, parameters)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_servicelist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "service", ordering="service_name")
    output = []
    for x in data["results"]:
        output.append(
            {
                "name": x["service_name"],
                "image path": x.get("image_path", None),
                "fullpath": x.get("binaryinfo", {}).get("fullpath", ""),
                "signed": x.get("binaryinfo", {})
                .get("binaryinfo", {})
                .get("signed", False),
                "md5": x.get("binaryinfo", {}).get("binaryinfo", {}).get("md5"),
            }
        )

    readable_output = tableToMarkdown(
        "Service List",
        output,
        headers=["name", "image_path", "fullpath", "signed", "md5"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Service",
        outputs_key_field="md5",
        outputs=output,
    )


def job_startuplist(client, args):
    args["action"] = "getStartupFileList"
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_startuplist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "startup", ordering="filename")
    output = []
    for x in data["results"]:
        output.append(
            {
                "startup_name": x["filename"],
                "startup_fullpath": x.get("fullpathfilename", x.get("fullpathname")),
                "fullpath": x.get("binaryinfo", {}).get("fullpath", ""),
                "signed": x.get("binaryinfo", {})
                .get("binaryinfo", {})
                .get("signed", False),
                "md5": x.get("binaryinfo", {}).get("binaryinfo", {}).get("md5"),
            }
        )

    readable_output = tableToMarkdown(
        "Startup List",
        output,
        headers=["startup_name", "startup_fullpath", "fullpath", "signed", "md5"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Startup",
        outputs_key_field="md5",
        outputs=output,
    )


def job_wmilist(client, args):
    args["action"] = "getWMI"
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_wmilist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "wmi", ordering="filename")
    output = []
    for x in data["results"]:
        output.append(
            {
                "filter to consumer type": x["filtertoconsumertype"],
                "event filter name": x["eventfiltername"],
                "event consumer name": x["eventconsumername"],
                "event filter": x["eventfilter"],
                "consumer data": x["consumerdata"],
            }
        )

    readable_output = tableToMarkdown(
        "WMI List",
        output,
        headers=[
            "filter to consumer type",
            "event filter name",
            "event consumer name",
            "event filter",
            "consumer data",
        ],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output, outputs_prefix="Harfanglab.Wmi", outputs=output
    )


def job_processlist(client, args):
    args["action"] = "getProcessList"
    parameters = {
        "getConnectionsList": False,
        "getHandlesList": False,
        "getSignaturesInfo": True,
    }
    ret, job_id = job_create(client, args, parameters)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_processlist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "process", ordering="name")
    output = []
    for x in data["results"]:
        output.append(
            {
                "name": x["name"],
                "session": x.get("session", None),
                "username": x.get("username", None),
                "integrity": x.get("integrity_level", None),
                "pid": x["pid"],
                "ppid": x["ppid"],
                "cmdline": x["cmdline"],
                "fullpath": x.get("binaryinfo", {}).get("fullpath", ""),
                "signed": x.get("binaryinfo", {})
                .get("binaryinfo", {})
                .get("signed", False),
                "md5": x.get("binaryinfo", {}).get("binaryinfo", {}).get("md5"),
            }
        )

    readable_output = tableToMarkdown(
        "Process List",
        output,
        headers=[
            "name",
            "session",
            "username",
            "integrity",
            "pid",
            "ppid",
            "cmdline",
            "fullpath",
            "signed",
            "md5",
        ],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Process",
        outputs_key_field="md5",
        outputs=output,
    )


def job_networkconnectionlist(client, args):
    args["action"] = "getProcessList"
    parameters = {
        "getConnectionsList": True,
        "getHandlesList": False,
        "getSignaturesInfo": True,
    }
    ret, job_id = job_create(client, args, parameters)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_networkconnectionlist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "process", ordering="name")
    output = []
    for x in data["results"]:
        if "connections" in x:
            fullpath = x.get("binaryinfo", {}).get("fullpath", "")
            signed = x.get("binaryinfo", {}).get("binaryinfo", {}).get("signed", False)
            md5 = x.get("binaryinfo", {}).get("binaryinfo", {}).get("md5")

            for connection in x["connections"]:
                output.append(
                    {
                        "state": connection["connection_state"],
                        "protocol": connection["protocol"],
                        "version": connection["ip_version"],
                        "src_addr": connection["src_addr"],
                        "src_port": connection["src_port"],
                        "dst_addr": connection.get("dst_addr", None),
                        "dst_port": connection.get("dst_port", None),
                        "fullpath": fullpath,
                        "signed": signed,
                        "md5": md5,
                    }
                )

    readable_output = tableToMarkdown(
        "Network Connection List",
        output,
        headers=[
            "state",
            "protocol",
            "version",
            "src_addr",
            "src_port",
            "dst_addr",
            "dst_port",
            "fullpath",
            "signed",
            "md5",
        ],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.NetworkConnection",
        outputs_key_field="md5",
        outputs=output,
    )


def job_networksharelist(client, args):
    args["action"] = "getNetworkShare"
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_networksharelist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "networkshare", ordering="name")
    output = []
    for x in data["results"]:
        output.append(
            {
                "Name": x.get("name", ""),
                "Caption": x.get("caption", ""),
                "Description": x.get("description", ""),
                "Path": x.get("path", ""),
                "Status": x.get("status", ""),
                "Share type val": x.get("sharetypeval", ""),
                "Share type": x.get("sharetype", ""),
                "Hostname": x.get("agent", {}).get("hostname", ""),
            }
        )

    readable_output = tableToMarkdown(
        "Network Share List",
        output,
        headers=[
            "Name",
            "Caption",
            "Description",
            "Path",
            "Status",
            "Share type val",
            "Share type",
            "Hostname",
        ],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.NetworkShare",
        outputs_key_field="Name",
        outputs=output,
    )


def job_sessionlist(client, args):
    args["action"] = "getSessions"
    ret, job_id = job_create(client, args)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_sessionlist(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "session", ordering="name")
    output = []
    for x in data["results"]:
        output.append(
            {
                "Logon Id": x.get("logonid", ""),
                "Authentication package": x.get("authenticationpackage", ""),
                "Logon type": x.get("logontype", ""),
                "Logon type str": x.get("logontypestr", ""),
                "Session start time": x.get("sessionstarttime", ""),
                "Hostname": x.get("agent", {}).get("hostname", ""),
            }
        )

    readable_output = tableToMarkdown(
        "Session List",
        output,
        headers=[
            "Logon Id",
            "Authentication package",
            "Logon type",
            "Logon type str",
            "Session start time",
            "Hostname",
        ],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Session",
        outputs_key_field="Logon Id",
        outputs=output,
    )


def job_ioc(client, args):
    args["action"] = "IOCScan"

    search_in_path = args.get("search_in_path", None)
    filename = args.get("filename", None)
    filepath = args.get("filepath", None)
    filepath_regex = args.get("filepath_regex", None)
    registry = args.get("registry", None)
    filehash = args.get("hash", None)
    filehash_size = args.get("hash_filesize", None)
    filesize = args.get("filesize", None)

    # filepath_regex = args.get('filepath_regex', None)
    # registry = args.get('registry', None)

    job_parameters = {"values": []}  # type: Dict[str,List[Dict[str,Any]]]
    good = False

    size = None

    if filesize:
        size = arg_to_number(filesize)
    elif filehash_size:
        size = arg_to_number(filehash_size)

    if filename is not None:
        job_parameters["values"].append(
            {"global": False, "size": size, "type": "filename", "value": filename}
        )
        good = True
    if filepath is not None:
        job_parameters["values"].append(
            {"global": False, "type": "filepath", "value": filepath}
        )
        good = True
    if filehash is not None:
        job_parameters["values"].append(
            {"global": False, "size": size, "type": "hash", "value": filehash}
        )
        good = True
    if registry is not None:
        job_parameters["values"].append(
            {"global": False, "type": "registry", "value": registry}
        )
        good = True
    if filepath_regex is not None:
        job_parameters["values"].append(
            {"global": False, "type": "regex", "value": filepath_regex}
        )
        good = True

    if good and search_in_path is not None:
        job_parameters["values"].append(
            {"global": True, "type": "path", "value": search_in_path}
        )

    if not good:
        return False

    ret, job_id = job_create(client, args, job_parameters, can_use_previous_job=False)
    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_ioc(client, args):
    job_id = args.get("job_id", None)
    common_result()

    data = client.job_data(job_id, "ioc", ordering="name")
    output = []
    for x in data["results"]:
        output.append(
            {
                "type": x["hit_type"],
                "search_value": x["search_value"],
                "fullpath": x.get("binaryinfo", {}).get("fullpath", ""),
                "signed": x.get("binaryinfo", {})
                .get("binaryinfo", {})
                .get("signed", False),
                "md5": x.get("binaryinfo", {}).get("binaryinfo", {}).get("md5"),
                "registry_path": x.get("found_registry_path"),
                "registry_key": x.get("found_registry_key"),
                "registry_value": x.get("found_registry_value"),
            }
        )

    readable_output = tableToMarkdown(
        "IOC Found List",
        output,
        headers=[
            "type",
            "search_value",
            "fullpath",
            "signed",
            "md5",
            "registry_path",
            "registry_key",
            "registry_value",
        ],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.IOC",
        outputs_key_field="md5",
        outputs=output,
    )


def global_job_artifact(client, args, parameters, artifact_type):
    args["action"] = "collectRAWEvidences"
    ret, job_id = job_create(client, args, parameters, can_use_previous_job=False)

    if not ret:
        return False

    return common_job(job_id, args["action"])


def global_result_artifact(client, args, artifact_type):
    job_id = args.get("job_id", None)
    common_result()

    result = {}
    info = get_job_status(client, job_id)
    result = info

    if info["Status"] != "finished":
        return CommandResults(
            readable_output=f"Job results not available (Job status: {info['Status']})",
            outputs_prefix="Harfanglab.Artifact",
        )

    base_url = client._base_url
    data = client.job_data(job_id, "artifact")
    api_token = None
    token = client.get_api_token()
    if "api_token" in token:
        api_token = token["api_token"]

    output = []
    for i in range(len(data["results"])):
        result = data["results"][i]
        if api_token is not None:
            result["download_link"] = (
                f"{base_url}/api/data/investigation/artefact/Artefact/{result['id']}/download/"
            )
            result["download_link"] += f"?hl_expiring_key={api_token}"
        else:
            result["download_link"] = "N/A"

        output.append(
            {
                "hostname": result["agent"]["hostname"],
                "msg": result["msg"],
                "size": result["size"],
                "download link": result["download_link"],
            }
        )

    readable_output = tableToMarkdown(
        f"{artifact_type} download list",
        output,
        headers=["hostname", "msg", "size", "download link"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Artifact",
        outputs=output,
    )


def job_artifact_mft(client, args):
    parameters = {
        "hives": False,
        "evt": False,
        "mft": True,
        "prefetch": False,
        "usn": False,
        "logs": False,
        "fs": False,
    }
    return global_job_artifact(client, args, parameters, "MFT")


def result_artifact_mft(client, args):
    return global_result_artifact(client, args, "MFT")


def job_artifact_evtx(client, args):
    parameters = {
        "hives": False,
        "evt": True,
        "mft": False,
        "prefetch": False,
        "usn": False,
        "logs": False,
        "fs": False,
    }
    return global_job_artifact(client, args, parameters, "EVTX")


def result_artifact_evtx(client, args):
    return global_result_artifact(client, args, "EVTX")


def job_artifact_logs(client, args):
    parameters = {
        "hives": False,
        "evt": False,
        "mft": False,
        "prefetch": False,
        "usn": False,
        "logs": True,
        "fs": False,
    }
    return global_job_artifact(client, args, parameters, "LOGS")


def result_artifact_logs(client, args):
    return global_result_artifact(client, args, "LOGS")


def job_artifact_fs(client, args):
    parameters = {
        "hives": False,
        "evt": False,
        "mft": False,
        "prefetch": False,
        "usn": False,
        "logs": False,
        "fs": True,
    }
    return global_job_artifact(client, args, parameters, "FS")


def result_artifact_fs(client, args):
    return global_result_artifact(client, args, "FS")


def job_artifact_hives(client, args):
    parameters = {
        "hives": True,
        "evt": False,
        "mft": False,
        "prefetch": False,
        "usn": False,
        "logs": False,
        "fs": False,
    }
    return global_job_artifact(client, args, parameters, "HIVES")


def result_artifact_hives(client, args):
    return global_result_artifact(client, args, "HIVES")


def job_artifact_all(client, args):
    parameters = {
        "hives": True,
        "evt": True,
        "mft": True,
        "prefetch": True,
        "usn": True,
        "logs": True,
        "fs": True,
    }
    return global_job_artifact(client, args, parameters, "ALL")


def result_artifact_all(client, args):
    return global_result_artifact(client, args, "ALL")


def job_artifact_downloadfile(client, args):
    args["action"] = "downloadFile"
    filename = args.get("filename", None)
    parameters = {"filename": filename}

    ret, job_id = job_create(client, args, parameters, can_use_previous_job=False)
    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_artifact_downloadfile(client, args):
    job_id = args.get("job_id", None)
    common_result()

    base_url = client._base_url
    data = client.job_data(job_id, "artifact", ordering="name")

    api_token = None
    token = client.get_api_token()
    if "api_token" in token:
        api_token = token["api_token"]

    output = []
    for x in data["results"]:
        if api_token is not None:
            link = f"{base_url}/api/data/investigation/artefact/Artefact/{x['id']}/download/?hl_expiring_key={api_token}"
        else:
            link = "N/A"

        output.append(
            {
                "hostname": x["agent"]["hostname"],
                "msg": x["msg"],
                "size": x["size"],
                "download link": link,
            }
        )

    readable_output = tableToMarkdown(
        "file download list",
        output,
        headers=["hostname", "msg", "size", "download link"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.DownloadFile",
        outputs=output,
    )


def job_artifact_ramdump(client, args):
    args["action"] = "memoryDumper"

    ret, job_id = job_create(client, args, can_use_previous_job=False)
    if not ret:
        return False

    return common_job(job_id, args["action"])


def result_artifact_ramdump(client, args):
    job_id = args.get("job_id", None)
    common_result()

    base_url = client._base_url
    data = client.job_data(job_id, "artifact", ordering="name")

    api_token = None
    token = client.get_api_token()
    if "api_token" in token:
        api_token = token["api_token"]

    output = []
    for x in data["results"]:
        link = (
            f"{base_url}/api/data/investigation/artefact/Artefact/{x['id']}/download/"
        )
        link += f"?hl_expiring_key={api_token}"
        output.append(
            {
                "hostname": x["agent"]["hostname"],
                "msg": x["msg"],
                "size": x["size"],
                "download link": link,
            }
        )

    readable_output = tableToMarkdown(
        "Ramdump list",
        output,
        headers=["hostname", "msg", "size", "download link"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Ramdump",
        outputs=output,
    )


def get_process_graph(client, args):
    process_uuid = args.get("process_uuid", None)

    data = client.get_process_graph(process_uuid)

    return CommandResults(
        outputs_prefix="Harfanglab.ProcessGraph",
        outputs_key_field="current_process_id",
        outputs=data,
    )


def search_whitelist(client, args):
    keyword = args.get("keyword", None)
    provided_by_hlab = args.get("provided_by_hlab", False)

    data = client.search_whitelist(keyword, provided_by_hlab)

    for wl in data["results"]:
        criteria = []
        for c in wl["criteria"]:
            criteria.append(f"{c['field']} {c['operator']} {c['value']}")
        wl["criteria_str"] = ", ".join(criteria)

    readable_output = tableToMarkdown(
        f"Whitelists found for keyword: {keyword}",
        data["results"],
        headers=[
            "comment",
            "id",
            "creation_date",
            "last_update",
            "target",
            "criteria_str",
            "sigma_rule_name",
        ],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Harfanglab.Whitelists",
        outputs=data["results"],
    )


def add_whitelist(client, args):
    comment = args.get("comment", None)
    sigma_rule_id = args.get("sigma_rule_id", "")
    target = args.get("target", "all")
    field = args.get("field", None)
    case_insensitive = args.get("case_insensitive", True)
    operator = args.get("operator", "eq")
    value = args.get("value", None)

    message = None
    data = None

    if target not in [
        "all",
        "sigma",
        "yara",
        "hlai",
        "vt",
        "ransom",
        "orion",
        "glimps",
        "cape",
        "driver",
    ]:
        message = (
            "Invalid target. "
            'Target must be "all", "sigma", '
            '"yara", "hlai", "vt", "ransom", '
            '"orion", "glimps", "cape" or "driver"'
        )
    elif operator not in ["eq", "regex", "contains"]:
        raise ValueError(
            "Invalid operator - operator must be 'eq', 'regex' or 'contains'"
        )
    else:
        data = client.add_whitelist(
            comment, sigma_rule_id, target, field, case_insensitive, operator, value
        )
        message = f"Successfully added whitelist (id: {data['id']})"

    return CommandResults(
        readable_output=message, outputs_prefix="Harfanglab.Whitelists", outputs=data
    )


def add_criterion_to_whitelist(client, args):
    id = args.get("id", None)
    field = args.get("field", None)
    case_insensitive = args.get("case_insensitive", True)
    operator = args.get("operator", "eq")
    value = args.get("value", None)

    message = None
    data = None

    if operator not in ["eq", "regex", "contains"]:
        raise ValueError(
            "Invalid operator - operator must be 'eq', 'regex' or 'contains'"
        )
    else:
        data = client.add_criterion_to_whitelist(
            id, field, case_insensitive, operator, value
        )
        message = "Successfully added criterion to whitelist"

    return CommandResults(
        readable_output=message, outputs_prefix="Harfanglab.Whitelists", outputs=data
    )


def delete_whitelist(client, args):
    id = args.get("id", None)

    client.delete_whitelist(id)

    return CommandResults(readable_output="Successfully deleted whitelist")


def hunt_search_hash(client, args):
    filehash = args.get("hash", None)
    common_result()

    results = []

    if isinstance(filehash, list):
        for i in filehash:
            args["hash"] = i
            hunt_search_hash(client, args)
        return
    else:
        data = client.data_hash_search(filehash=filehash)
        prefetchs = []
        curr_running = False
        prev_runned = False

        if len(data["data"]) == 0:
            currently_running = str(curr_running) + " (0 are running)"
            previously_executed = str(prev_runned) + " (0 were previously executed)"
            prefetchs.append(
                {
                    "process associated to hash currently running": currently_running,
                    "process associated to hash was previously executed": previously_executed,
                }
            )

            outputs = {"hash": filehash, "curr_running": 0, "prev_runned": 0}
            results.append(
                CommandResults(
                    outputs_prefix="Harfanglab.Hash",
                    outputs_key_field="hash",
                    outputs=outputs,
                    readable_output=tableToMarkdown(
                        "Hash search results", outputs, removeNull=True
                    ),
                )
            )

        for x in data["data"]:
            if x["processCount"] > 0:
                curr_running = True
            if x["telemetryProcessCount"] > 0:
                prev_runned = True
            currently_running = (
                str(curr_running) + " (" + str(x["processCount"]) + " are running)"
            )
            previously_executed = (
                str(prev_runned)
                + " ("
                + str(x["telemetryProcessCount"])
                + " were previously executed)"
            )
            prefetchs.append(
                {
                    "process associated to hash currently running": currently_running,
                    "process associated to hash was previously executed": previously_executed,
                }
            )

            outputs = {
                "hash": x["title"],
                "curr_running": x["processCount"],
                "prev_runned": x["telemetryProcessCount"],
            }
            results.append(
                CommandResults(
                    outputs_prefix="Harfanglab.Hash",
                    outputs_key_field="hash",
                    outputs=outputs,
                    readable_output=tableToMarkdown(
                        "Hash search results", outputs, removeNull=True
                    ),
                )
            )

        return_results(results)


def hunt_search_running_process_hash(client, args):
    filehash = args.get("hash", None)
    common_result()

    if isinstance(filehash, list):
        for i in filehash:
            args["hash"] = i
            hunt_search_running_process_hash(client, args)
        return None
    else:
        data = client.invest_running_process(filehash=filehash)
        prefetchs = []
        for x in data["results"]:
            prefetchs.append(
                {
                    "Hostname": x["agent"]["hostname"],
                    "Domain": x["agent"].get("domainname", ""),
                    "Username": x["username"],
                    "OS": x["agent"]["osproducttype"],
                    "OS Version": x["agent"]["osversion"],
                    "Binary Path": x["binaryinfo"]["fullpath"],
                    "Hash": filehash,
                    "Create timestamp": x["create_time"],
                    "Is maybe hollow": x["maybe_hollow"],
                }
            )

        readable_output = tableToMarkdown(
            "War room overview",
            prefetchs,
            headers=[
                "Hostname",
                "Domain",
                "Username",
                "OS",
                "OS Version",
                "Binary Path",
                "Hash",
                "Create timestamp",
                "Is maybe hollow",
            ],
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="Harfanglab.HuntRunningProcessSearch",
            outputs_key_field="hash",
            outputs=prefetchs,
            readable_output=readable_output,
        )


def hunt_search_runned_process_hash(client, args):
    filehash = args.get("hash", None)
    common_result()

    if isinstance(filehash, list):
        for i in filehash:
            args["hash"] = i
            hunt_search_runned_process_hash(client, args)
        return None
    else:
        data = client.invest_runned_process(filehash=filehash)
        prefetchs = []
        for x in data["results"]:
            prefetchs.append(
                {
                    "Hostname": x["agent"]["hostname"],
                    "Domain": x["agent"].get("domainname", ""),
                    "Username": x["username"],
                    "OS": x["agent"]["osproducttype"],
                    "OS Version": x["agent"]["osversion"],
                    "Binary Path": x["image_name"],
                    "Hash": filehash,
                    "Create timestamp": x.get("pe_timestamp", ""),
                }
            )

        readable_output = tableToMarkdown(
            "War room overview",
            prefetchs,
            headers=[
                "Hostname",
                "Domain",
                "Username",
                "OS",
                "Binary Path",
                "Create timestamp",
            ],
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix="Harfanglab.HuntRunnedProcessSearch",
            outputs_key_field="hash",
            outputs=prefetchs,
            readable_output=readable_output,
        )


def isolate_endpoint(client, args) -> CommandResults:
    agentid = args.get("agent_id", None)
    data = client.isolate_endpoint(agentid)

    context = {"Status": False, "Message": ""}  # type: Dict[str,Any]

    if agentid in data["requested"]:
        context["Status"] = True
        context["Message"] = "Agent isolation successfully requested"

    if agentid in data["policy_not_allowed"]:
        context["Status"] = False
        context["Message"] = (
            "Agent isolation request failed (not allowed by the agent policy)"
        )

    return CommandResults(
        outputs_prefix="Harfanglab.Isolation",
        outputs=context,
        readable_output=context["Message"],
    )


def deisolate_endpoint(client, args) -> CommandResults:
    agentid = args.get("agent_id", None)
    data = client.deisolate_endpoint(agentid)

    context = {"Status": False, "Message": ""}  # type: Dict[str,Any]

    if agentid in data["requested"]:
        context["Status"] = True
        context["Message"] = "Agent deisolation successfully requested"

    return CommandResults(
        outputs_prefix="Harfanglab.Unisolation",
        outputs=context,
        readable_output=context["Message"],
    )


def change_security_event_status(client, args) -> CommandResults:
    eventid = args.get("security_event_id", None)
    status = args.get("status", None)

    client.change_security_event_status(eventid, status)

    context = {}
    context["Message"] = f"Status for security event {eventid} changed to {status}"

    return CommandResults(outputs=context, readable_output=context["Message"])


def add_ioc_to_source(client, args):
    ioc_value = args.get("ioc_value", None)
    ioc_type = args.get("ioc_type", None)
    ioc_comment = args.get("ioc_comment", "")
    ioc_status = args.get("ioc_status", "")
    source_name = args.get("source_name", None)

    results = client.list_sources(source_type="ioc", source_name=source_name)

    source_id = None

    for source in results["results"]:
        if source["name"] == source_name:
            source_id = source["id"]

    results = client.search_ioc(ioc_value, source_id)

    context = {}
    if results["count"] > 0:
        context["Message"] = f"IOC {ioc_value} already exists in source {source_name}"
    else:
        client.add_ioc_to_source(
            ioc_value, ioc_type, ioc_comment, ioc_status, source_id
        )
        context["Message"] = (
            f"IOC {ioc_value} of type {ioc_type} added to source {source_name} with {ioc_status} status"
        )

    return CommandResults(outputs=context, readable_output=context["Message"])


def delete_ioc_from_source(client, args):
    ioc_value = args.get("ioc_value", None)
    source_name = args.get("source_name", None)

    results = client.list_sources(source_type="ioc", source_name=source_name)

    source_id = None

    for source in results["results"]:
        if source["name"] == source_name:
            source_id = source["id"]

    results = client.search_ioc(ioc_value=ioc_value, source_id=source_id)

    context = {}
    if results["count"] > 0:
        ioc_id = results["results"][0]["id"]
        client.delete_ioc(ioc_id)
        context["Message"] = f"IOC {ioc_value} removed from source {source_name}"
    else:
        context["Message"] = f"IOC {ioc_value} does not exist in source {source_name}"

    return CommandResults(outputs=context, readable_output=context["Message"])


class Telemetry:
    def __init__(self):
        self.params = {}

        # Keys is an array of tuple with (args field, filter field)
        self.keys = [
            ("to_date", "@event_create_date__lte"),
            ("from_date", "@event_create_date__gte"),
            ("hostname", "agent.hostname"),
            ("limit", "limit"),
        ]

        # Output keys is an array of tuple with (output name `label`, data field)
        self.output_keys = []

        self.title = ""
        self.telemetry_type = ""

    def _add_hash_parameters(self, binary_hash=None):
        if binary_hash is not None:
            if len(binary_hash) == 64:
                hash_type = "sha256"
            elif len(binary_hash) == 40:
                hash_type = "sha1"
            elif len(binary_hash) == 32:
                hash_type = "md5"
            else:
                hash_type = "unknown"
                demisto.debug(f"{hash_type=}")

            self.params[f"hashes.{hash_type}"] = binary_hash

    def _construct_output(self, results, client=None):
        # Global helper to construct output list
        return _construct_output(results, self.output_keys)

    def get_telemetry(self, client, args):
        self.params = _construct_request_parameters(args, self.keys, params=self.params)

        # Execute request with params
        return client.telemetry_data(self.telemetry_type, self.params)

    def telemetry(self, client, args):
        data = self.get_telemetry(client, args)
        output = self._construct_output(data["results"], client)

        # Determines headers for readable output
        headers = list(output[0].keys()) if len(output) > 0 else []
        readable_output = tableToMarkdown(
            self.title, output, headers=headers, removeNull=True
        )

        return CommandResults(
            outputs_prefix=f"Harfanglab.Telemetry{self.telemetry_type}",
            outputs=output,
            readable_output=readable_output,
        )


class TelemetryProcesses(Telemetry):
    def __init__(self):
        super().__init__()

        self.keys += [
            ("process_name", "process_name"),
            ("image_name", "image_name"),
        ]
        self.output_keys = [
            ("process_unique_id", "process_unique_id"),
            ("create date", "@event_create_date"),
            ("hostname", ["agent", "hostname"]),
            ("process name", "process_name"),
            ("image name", "image_name"),
            ("commandline", "commandline"),
            ("integrity level", "integrity_level"),
            ("parent image", "parent_image"),
            ("parent commandline", "parent_commandline"),
            ("username", "username"),
            ("signed", "signed"),
            ("signer", ["signature_info", "signer_info", "display_name"]),
            ("sha256", ["hashes", "sha256"]),
        ]

        self.title = "Processes list"
        self.telemetry_type = "processes"

    def telemetry(self, client, args):
        binary_hash = args.get("hash", None)
        self._add_hash_parameters(binary_hash)
        return super().telemetry(client, args)


class TelemetryDNSResolution(Telemetry):
    def __init__(self):
        super().__init__()

        self.keys += [
            ("requested_name", "requested_name"),
            ("query_type", "query_type"),
        ]
        self.output_keys = [
            ("create date", "@event_create_date"),
            ("hostname", ["agent", "hostname"]),
            ("agentid", ["agent", "agentid"]),
            ("process image path", "process_image_path"),
            ("pid", "pid"),
            ("process unique id", "process_unique_id"),
            ("requested name", "requested_name"),
            ("query type", "query_type"),
            ("IP addresses", "ip_addresses"),
            ("tenant", "tenant"),
        ]

        self.title = "DNS Resolutions"
        self.telemetry_type = "dns"

    def telemetry(self, client, args):
        return super().telemetry(client, args)


class TelemetryWindowsAuthentication(Telemetry):
    def __init__(self):
        super().__init__()

        self.keys += [
            ("source_address", "source_address"),
            ("success", "success"),
            ("source_username", "source_username"),
            ("target_username", "target_username"),
            ("logon_title", "windows.logon_title"),
            ("logon_type", "windows.logon_type"),
        ]
        self.output_keys = [
            ("timestamp", "@timestamp"),
            ("hostname", ["agent", "hostname"]),
            ("agentid", ["agent", "agentid"]),
            ("source address", "source_address"),
            ("source username", "source_username"),
            ("target username", "target_username"),
            ("success", "success"),
            ("event id", ["windows", "event_id"]),
            ("event title", ["windows", "event_title"]),
            ("logon process name", ["windows", "logon_process_name"]),
            ("logon title", ["windows", "logon_title"]),
            ("logon type", ["windows", "logon_type"]),
            ("process name", "process_name"),
        ]

        self.title = "Windows Authentications"
        self.telemetry_type = "windows_authentications"


class TelemetryLinuxAuthentication(Telemetry):
    def __init__(self):
        super().__init__()

        self.keys += [
            ("source_address", "source_address"),
            ("success", "success"),
            ("source_username", "source_username"),
            ("target_username", "target_username"),
        ]
        self.output_keys = [
            ("timestamp", "@timestamp"),
            ("hostname", ["agent", "hostname"]),
            ("agentid", ["agent", "agentid"]),
            ("source address", "source_address"),
            ("source username", "source_username"),
            ("target username", "target_username"),
            ("success", "success"),
            ("tty", ["linux", "tty"]),
            ("target uid", ["linux", "target_uid"]),
            ("target group", ["linux", "target_group"]),
            ("target gid", ["linux", "target_gid"]),
            ("process name", "process_name"),
            ("pid", "pid"),
        ]

        self.title = "Linux Authentications"
        self.telemetry_type = "linux_authentications"


class TelemetryMacosAuthentication(Telemetry):
    def __init__(self):
        super().__init__()

        self.keys += [
            ("source_address", "source_address"),
            ("success", "success"),
            ("source_username", "source_username"),
            ("target_username", "target_username"),
        ]
        self.output_keys = [
            ("timestamp", "@timestamp"),
            ("hostname", ["agent", "hostname"]),
            ("agentid", ["agent", "agentid"]),
            ("source address", "source_address"),
            ("source username", "source_username"),
            ("target username", "target_username"),
            ("success", "success"),
            ("tty", ["linux", "tty"]),
            ("target uid", ["linux", "target_uid"]),
            ("target group", ["linux", "target_group"]),
            ("target gid", ["linux", "target_gid"]),
            ("process name", "process_name"),
            ("pid", "pid"),
        ]

        self.title = "Macos Authentications"
        self.telemetry_type = "macos_authentications"


class TelemetryNetwork(Telemetry):
    def __init__(self):
        super().__init__()

        self.keys += [
            ("source_address", "saddr"),
            ("source_port", "sport"),
            ("destination_address", "daddr"),
            ("destination_port", "dport"),
        ]
        self.output_keys = [
            ("create date", "@event_create_date"),
            ("hostname", ["agent", "hostname"]),
            ("image name", "image_name"),
            ("username", "username"),
            ("source address", "saddr"),
            ("source port", "sport"),
            ("destination addr", "daddr"),
            ("destination port", "dport"),
            ("direction", "direction"),
        ]

        self.title = "Network list"
        self.telemetry_type = "network"


class TelemetryEventLog(Telemetry):
    def __init__(self):
        super().__init__()

        self.keys += [
            ("event_id", "event_id"),
        ]
        self.output_keys = [
            ("create date", "@event_create_date"),
            ("hostname", ["agent", "hostname"]),
            ("event id", "event_id"),
            ("source name", "source_name"),
            ("log name", "log_name"),
            ("keywords", "keywords"),
            ("event data", "event_data"),
            ("level", "level"),
        ]

        self.title = "Event Log list"
        self.telemetry_type = "eventlog"


class TelemetryBinary(Telemetry):
    def __init__(self):
        super().__init__()

        self.keys = [
            ("name", "names"),
            ("path", "fullpaths"),
            ("filesize_min", "filesize__gte"),
            ("filesize_max", "filesize__lte"),
            ("exact_filesize", "filesize"),
        ]
        self.output_keys += [
            ("process name", "process_name"),
            ("image name", "image_name"),
            ("commandline", "commandline"),
            ("integrity level", "integrity_level"),
            ("parent image", "parent_image"),
            ("parent commandline", "parent_commandline"),
            ("username", "username"),
            ("signed", "signed"),
            ("signer", ["signature_info", "signer_info", "display_name"]),
            ("sha256", ["hashes", "sha256"]),
        ]

        self.title = "Binary list"
        self.telemetry_type = "binary"

        self.token: Optional[str] = None

    def _construct_output(self, results, client=None):
        """Download with an API token is not supported yet"""

        # can't use a property attr. here because we need the client object to
        # fetch an api token
        if not self.token:
            self.token = client.get_api_token().get("api_token")

        api_token = self.token

        output = []
        for x in results:
            for i in range(0, len(x["names"])):
                name = x["names"][i]
                path = x["paths"][i] if len(x["paths"]) > i else None

                link = None
                if x["downloaded"] == 0:
                    link = f"{client._base_url}/api/data/telemetry/Binary/download/{x['hashes']['sha256']}/"
                    if api_token:
                        link += f"?hl_expiring_key={api_token}"

                output.append(
                    {
                        "name": name,
                        "path": path,
                        "size": x["size"],
                        "signed": x.get("signed", ""),
                        "signer": x.get("signature_info", {})
                        .get("signer_info", {})
                        .get("display_name", None),
                        "sha256": x["hashes"].get("sha256", None),
                        "download link": link,
                    }
                )

        return output

    def telemetry(self, client, args):
        binary_hash = args.get("hash", None)
        self._add_hash_parameters(binary_hash)
        return super().telemetry(client, args)


@functools.lru_cache(maxsize=100)
def get_function_from_command_name(command: str) -> Fn:

    mapping: dict[str, Fn] = {
        "harfanglab-get-endpoint-info": get_endpoint_info,
        "harfanglab-endpoint-search": endpoint_search,
        "harfanglab-job-info": job_info,
        "harfanglab-job-pipelist": job_pipelist,
        "harfanglab-result-pipelist": result_pipelist,
        "harfanglab-job-prefetchlist": job_prefetchlist,
        "harfanglab-result-prefetchlist": result_prefetchlist,
        "harfanglab-job-runkeylist": job_runkeylist,
        "harfanglab-result-runkeylist": result_runkeylist,
        "harfanglab-job-scheduledtasklist": job_scheduledtasklist,
        "harfanglab-result-scheduledtasklist": result_scheduledtasklist,
        "harfanglab-job-driverlist": job_driverlist,
        "harfanglab-result-driverlist": result_driverlist,
        "harfanglab-job-servicelist": job_servicelist,
        "harfanglab-result-servicelist": result_servicelist,
        "harfanglab-job-processlist": job_processlist,
        "harfanglab-result-processlist": result_processlist,
        "harfanglab-job-networkconnectionlist": job_networkconnectionlist,
        "harfanglab-result-networkconnectionlist": result_networkconnectionlist,
        "harfanglab-job-networksharelist": job_networksharelist,
        "harfanglab-result-networksharelist": result_networksharelist,
        "harfanglab-job-sessionlist": job_sessionlist,
        "harfanglab-result-sessionlist": result_sessionlist,
        "harfanglab-job-persistencelist": job_linux_persistence_list,
        "harfanglab-result-persistencelist": result_linux_persistence_list,
        "harfanglab-job-ioc": job_ioc,
        "harfanglab-result-ioc": result_ioc,
        "harfanglab-job-startuplist": job_startuplist,
        "harfanglab-result-startuplist": result_startuplist,
        "harfanglab-job-wmilist": job_wmilist,
        "harfanglab-result-wmilist": result_wmilist,
        "harfanglab-job-artifact-mft": job_artifact_mft,
        "harfanglab-result-artifact-mft": result_artifact_mft,
        "harfanglab-job-artifact-hives": job_artifact_hives,
        "harfanglab-result-artifact-hives": result_artifact_hives,
        "harfanglab-job-artifact-evtx": job_artifact_evtx,
        "harfanglab-result-artifact-evtx": result_artifact_evtx,
        "harfanglab-job-artifact-logs": job_artifact_logs,
        "harfanglab-result-artifact-logs": result_artifact_logs,
        "harfanglab-job-artifact-filesystem": job_artifact_fs,
        "harfanglab-result-artifact-filesystem": result_artifact_fs,
        "harfanglab-job-artifact-all": job_artifact_all,
        "harfanglab-result-artifact-all": result_artifact_all,
        "harfanglab-job-artifact-downloadfile": job_artifact_downloadfile,
        "harfanglab-result-artifact-downloadfile": result_artifact_downloadfile,
        "harfanglab-job-artifact-ramdump": job_artifact_ramdump,
        "harfanglab-result-artifact-ramdump": result_artifact_ramdump,
        "harfanglab-telemetry-processes": TelemetryProcesses().telemetry,
        "harfanglab-telemetry-network": TelemetryNetwork().telemetry,
        "harfanglab-telemetry-eventlog": TelemetryEventLog().telemetry,
        "harfanglab-telemetry-binary": TelemetryBinary().telemetry,
        "harfanglab-telemetry-dns": TelemetryDNSResolution().telemetry,
        "harfanglab-telemetry-authentication-windows": TelemetryWindowsAuthentication().telemetry,
        "harfanglab-telemetry-authentication-linux": TelemetryLinuxAuthentication().telemetry,
        "harfanglab-telemetry-authentication-macos": TelemetryMacosAuthentication().telemetry,
        "harfanglab-telemetry-authentication-users": get_frequent_users,
        "harfanglab-telemetry-process-graph": get_process_graph,
        "harfanglab-hunt-search-hash": hunt_search_hash,
        "harfanglab-hunt-search-running-process-hash": hunt_search_running_process_hash,
        "harfanglab-hunt-search-runned-process-hash": hunt_search_runned_process_hash,
        "harfanglab-isolate-endpoint": isolate_endpoint,
        "harfanglab-deisolate-endpoint": deisolate_endpoint,
        "harfanglab-change-security-event-status": change_security_event_status,
        "harfanglab-assign-policy-to-agent": assign_policy_to_agent,
        "harfanglab-add-ioc-to-source": add_ioc_to_source,
        "harfanglab-delete-ioc-from-source": delete_ioc_from_source,
        "harfanglab-whitelist-search": search_whitelist,
        "harfanglab-whitelist-add": add_whitelist,
        "harfanglab-whitelist-add-criterion": add_criterion_to_whitelist,
        "harfanglab-whitelist-delete": delete_whitelist,
        "harfanglab-api-call": api_call,
        "fetch-incidents": fetch_incidents,
        "get-modified-remote-data": get_modified_remote_data,
        "get-remote-data": get_remote_data,
        "update-remote-system": update_remote_system,
        "get-mapping-fields": get_mapping_fields,
        "test-module": test_module,
    }

    return mapping[command]


def get_security_events(
    client,
    security_event_ids=None,
    min_created_timestamp=None,
    min_updated_timestamp=None,
    alert_status=None,
    alert_type=None,
    min_severity=DEFAULT_SEVERITY,
    max_fetch=None,
    fields=None,
    limit=MAX_NUMBER_OF_ALERTS_PER_CALL,
    ordering="alert_time",
    threat_id=None,
    extra_filters: dict[str, Any] = None,
):
    security_events = []

    agents: Dict[str, Any] = {}

    if security_event_ids:
        for sec_evt_id in security_event_ids:
            results = client._http_request(
                method="GET",
                url_suffix=f"/api/data/alert/alert/Alert/{sec_evt_id}/details/",
            )

            alert = results["alert"]

            # Retrieve additional endpoint information
            groups = []
            agent = None
            agentid = alert.get("agent", {}).get("agentid", None)
            if agentid:
                if agentid in agents:
                    agent = agents[agentid]
                else:
                    try:
                        agent = client.get_endpoint_info(agentid)
                    except Exception:
                        agent = None
                    agents[agentid] = agent

                if agent:
                    for g in agent.get("groups", []):
                        groups.append(g["name"])
                    alert["agent"]["policy_name"] = agent.get("policy", {}).get("name")
                    alert["agent"]["groups"] = groups

            security_events.append(alert)

        return security_events

    args = {
        "ordering": ordering,
        "level": ",".join(
            SEVERITIES[SEVERITIES.index(min_severity):]
        ).lower(),
        "limit": limit,
        "offset": 0,
    }  # type: Dict[str,Any]

    if isinstance(alert_status, list):
        args["status"] = ",".join(alert_status)
    elif alert_status == "ACTIVE":
        args["status"] = ",".join(["new", "probable_false_positive", "investigating"])
    elif alert_status == "CLOSED":
        args["status"] = ",".join(["closed", "false_positive"])

    if alert_type:
        args["alert_type"] = alert_type

    if min_created_timestamp:
        args["alert_time__gte"] = min_created_timestamp

    if min_updated_timestamp:
        args["last_update__gte"] = min_updated_timestamp

    if fields:
        args["fields"] = ",".join(fields)

    if threat_id:
        args["threat_key"] = threat_id

    if extra_filters:
        args.update(extra_filters)

    demisto.debug(f"Args for fetch_security_events: {args}")

    while True:
        results = client._http_request(
            method="GET", url_suffix="/api/data/alert/alert/Alert/", params=args
        )

        results_count: int = len(results["results"])

        if results_count == 0:
            break

        demisto.debug(f"{results_count} security events fetched...")

        for alert in results["results"]:
            # Retrieve additional endpoint information
            groups = []
            agent = None
            agentid = alert.get("agent", {}).get("agentid", None)
            if agentid:
                if agentid in agents:
                    agent = agents[agentid]
                else:
                    try:
                        agent = client.get_endpoint_info(agentid)
                    except Exception:
                        agent = None
                    agents[agentid] = agent

                if agent:
                    for g in agent.get("groups", []):
                        groups.append(g["name"])
                    alert["agent"]["policy_name"] = agent.get("policy", {}).get("name")
                    alert["agent"]["groups"] = groups

            security_events.append(alert)

            if max_fetch and len(security_events) >= max_fetch:
                break

        args["offset"] += results_count
        if (
            results["count"] == 0
            or not results["next"]
            or (max_fetch and len(security_events) >= max_fetch)
        ):
            break

    return security_events


def enrich_threat(client, threat):
    if not client or not threat or "id" not in threat:
        return

    threat_id = threat.get("id")

    if not threat_id:
        return

    # Get agents
    results = client.endpoint_search(
        threat_id=threat_id,
        fields=["id", "hostname", "domainname", "osproducttype", "ostype"],
    )
    threat["agents"] = results["results"]

    # Get users
    results = client.user_search(threat_id=threat_id)
    threat["impacted_users"] = results["results"]

    # Get rules
    args = assign_params(
        threat_id=threat_id, fields="rule_level,rule_name,security_event_count"
    )
    results = client._http_request(
        method="GET", url_suffix="/api/data/alert/alert/Threat/rules/", params=args
    )
    threat["rules"] = results["results"]


def get_threats(
    client,
    threat_ids=None,
    min_created_timestamp=None,
    min_updated_timestamp=None,
    threat_status=None,
    min_severity=DEFAULT_SEVERITY,
    max_fetch=None,
    fields=None,
    limit=MAX_NUMBER_OF_ALERTS_PER_CALL,
    ordering="last_seen",
    extra_filters: dict[str, Any] = None,
):
    threats = []

    if not threat_ids:
        threat_ids = []
        args = {
            "ordering": ordering,
            "level": ",".join(
                SEVERITIES[SEVERITIES.index(min_severity):]
            ).lower(),
            "limit": limit,
            "offset": 0,
        }  # type: Dict[str,Any]

        if isinstance(threat_status, list):
            args["status"] = ",".join(threat_status)
        elif threat_status == "ACTIVE":
            args["status"] = ",".join(["new", "investigating"])
        elif threat_status == "CLOSED":
            args["status"] = ",".join(["closed", "false_positive"])

        if min_created_timestamp:
            args["creation_date__gte"] = min_created_timestamp

        if min_updated_timestamp:
            args["last_update__gte"] = min_updated_timestamp

        if fields:
            args["fields"] = ",".join(fields)

        if extra_filters:
            args.update(extra_filters)

        demisto.debug(f"Args for get_threats: {args}")

        while True:
            results = client._http_request(
                method="GET", url_suffix="/api/data/alert/alert/Threat/", params=args
            )

            results_count: int = len(results["results"])

            if results_count == 0:
                break

            demisto.debug(f"{results_count} threats fetched...")

            for threat in results["results"]:
                threat_ids.append(threat["id"])

                if max_fetch and len(threat_ids) >= max_fetch:
                    break

            args["offset"] += results_count
            if (
                results["count"] == 0
                or not results["next"]
                or (max_fetch and len(threat_ids) >= max_fetch)
            ):
                break

    for threat_id in threat_ids:
        threat = client._http_request(
            method="GET", url_suffix=f"/api/data/alert/alert/Threat/{threat_id}/"
        )
        enrich_threat(client, threat)
        threats.append(threat)

    return threats


def get_modified_remote_data(
    client: Client,
    args: dict[str, Any],
) -> GetModifiedRemoteDataResponse:
    """Get list of modified/updated security events/threat ids on remote instance.

    Args:
        client: Demisto client to use. Initialized in the 'main' function.
        args:
            last_update: the last time this function as been executed.

    Returns:
        GetModifiedRemoteDataResponse object, which contains the list of
          modified/updated security events and threats ids on remote instance.
    """
    modified_remote_data_args = GetModifiedRemoteDataArgs(args)

    # every timestamp in remote instance are stored as UTC
    last_update: Optional[datetime] = dateparser.parse(
        modified_remote_data_args.last_update, settings={"TIMEZONE": "UTC"}
    )

    if not last_update:
        raise ValueError(f"Unable to parse '{modified_remote_data_args.last_update}'")

    if last_update.tzname() != "UTC":
        raise ValueError(
            f"Expect an 'UTC' datetime, get an '{last_update.tzname()}' one ({last_update})"
        )

    fetch_limit: int
    fetch_base_limit = 10000

    modified_incident_ids: list[str] = []

    security_events_to_update: list[SecurityEvent] = []
    threats_to_update: list[Threat] = []

    # Both for security events and threats, the 'fetch_limit' value will be
    # increase until everything that has been updated in the remote instance are
    # effectively fetched

    # Most of the time, only one 'for' loop will be enough
    # In rare case, two will be needed
    # In extreme case, more (e.g. the XSOAR haven't been synch. with the remote
    # instance for age)

    # A more clever way to fetch data, should be to use 'offset' and 'next' values

    for fetch_limit in (fetch_base_limit * i for i in itertools.count(start=1)):

        security_events_to_update.clear()
        security_events_to_update.extend(
            get_security_events(
                client=client,
                min_updated_timestamp=last_update.strftime("%Y-%m-%dT%H:%M:%SZ"),
                alert_type=args.get("alert_type"),
                min_severity=args.get("min_severity", DEFAULT_SEVERITY),
                fields=["id"],
                limit=fetch_limit,
                ordering="last_update",
            )
        )

        if len(security_events_to_update) < fetch_limit:
            break

    demisto.debug(f"Found {len(security_events_to_update)} security events to update")

    modified_incident_ids.extend(
        f"{IncidentType.SECURITY_EVENT}:{s['id']}" for s in security_events_to_update
    )

    for fetch_limit in (fetch_base_limit * i for i in itertools.count(start=1)):

        threats_to_update.clear()
        threats_to_update.extend(
            get_threats(
                client=client,
                min_updated_timestamp=last_update.strftime("%Y-%m-%dT%H:%M:%SZ"),
                min_severity=args.get("min_severity", DEFAULT_SEVERITY),
                fields=["id"],
                limit=fetch_limit,
                ordering="last_update",
            )
        )

        if len(threats_to_update) < fetch_limit:
            break

    demisto.debug(f"Found {len(threats_to_update)} threats to update")

    modified_incident_ids.extend(
        f"{IncidentType.THREAT}:{t['id']}" for t in threats_to_update
    )

    demisto.info(
        f"Found {len(modified_incident_ids)} incidents to update "
        f"({len(security_events_to_update)} security events, "
        f"{len(threats_to_update)} threats)"
    )

    return GetModifiedRemoteDataResponse(modified_incident_ids)


def set_updated_object(
    updated_object: Dict[str, Any],
    mirrored_data: Dict[str, Any],
    mirroring_fields: List[str],
):
    """
    Sets the updated object (in place) for the security event or threat we want to mirror in, from the mirrored data, according to
    the mirroring fields. In the mirrored data, the mirroring fields might be nested in a dict or in a dict inside a list (if so,
    their name will have a dot in it).
    Note that the fields that we mirror right now may have only one dot in them, so we only deal with this case.

    :param updated_object: The dictionary to set its values, so it will hold the fields we want to mirror in, with their values.
    :param mirrored_data: The data of the security event or threat we want to mirror in.
    :param mirroring_fields: The mirroring fields that we want to mirror in, given according to whether we want to mirror a
        security event or a threat.
    """

    # better use some recursive functions here...

    field: str
    root_field: str
    sub_field: str

    nested_mirrored_data: list | dict | None

    for field in mirroring_fields:

        # check that the field is present in the mirrored data from the EDR
        # (data can be null)
        if field in mirrored_data:
            updated_object[field] = mirrored_data[field]

        # if the field is not in mirrored_data, it might be a nested field - that has a . in its name
        elif "." in field:
            # only the first deep level is checked for now
            root_field, sub_field = field.split(".", 1)

            if root_field in mirrored_data:

                nested_mirrored_data = mirrored_data[root_field]

                if isinstance(nested_mirrored_data, list):
                    # if it is a list, it should hold a dictionary in it because it is a json structure
                    # assume nested_mirrored_data is a list of dictionaries
                    for nested_dict in nested_mirrored_data:
                        if sub_field in nested_dict:
                            updated_object[field] = nested_dict[sub_field]
                            # finding the field in the first time it is satisfying
                            break

                elif isinstance(nested_mirrored_data, dict):
                    if sub_field in nested_mirrored_data:
                        updated_object.setdefault(root_field, {})
                        updated_object[root_field][sub_field] = nested_mirrored_data[
                            sub_field
                        ]

                else:
                    demisto.debug(
                        f"Nested field '{field}' is not a list, nor a dictionary"
                    )
            else:
                demisto.debug(f"Nested field '{field}' doesn't appear to exist")
        else:
            demisto.debug(f"Field '{field}' doesn't appear to exist")


def get_remote_secevent_data(client, remote_incident_id: str):
    """
    Called every time get-remote-data command runs on a security event.
    Gets the relevant security event entity from the remote system (HarfangLab EDR). The remote system returns a list with this
    entity in it. We take from this entity only the relevant incoming mirroring fields, in order to do the mirroring.
    """
    mirrored_data_list = get_security_events(
        client, security_event_ids=[remote_incident_id]
    )
    mirrored_data = mirrored_data_list[0]

    if "status" in mirrored_data:
        mirrored_data["status"] = STATUS_HFL_TO_XSOAR.get(mirrored_data.get("status"))

    updated_object: Dict[str, Any] = {"incident_type": "Hurukai alert"}
    set_updated_object(updated_object, mirrored_data, HFL_SECURITY_EVENT_INCOMING_ARGS)
    return mirrored_data, updated_object


def get_remote_threat_data(client, remote_incident_id: str):
    """
    Called every time get-remote-data command runs on a threat.
    Gets the relevant threat entity from the remote system (HarfangLab EDR). The remote system returns a list with this
    entity in it. We take from this entity only the relevant incoming mirroring fields, in order to do the mirroring.
    """
    mirrored_data_list = get_threats(client, threat_ids=[remote_incident_id])
    mirrored_data = mirrored_data_list[0]

    if "status" in mirrored_data:
        mirrored_data["status"] = STATUS_HFL_TO_XSOAR.get(mirrored_data.get("status"))

    updated_object: Dict[str, Any] = {"incident_type": "Hurukai threat"}
    set_updated_object(updated_object, mirrored_data, HFL_THREAT_INCOMING_ARGS)
    return mirrored_data, updated_object


def close_in_xsoar(entries: List, remote_incident_id: str, incident_type_name: str):
    demisto.debug(f"Close incident '{remote_incident_id}'")
    entries.append(
        {
            "Type": EntryType.NOTE,
            "Contents": {
                "dbotIncidentClose": True,
                "closeReason": f"{incident_type_name} was closed on HarfangLab EDR",
            },
            "ContentsFormat": EntryFormat.JSON,
        }
    )


def reopen_in_xsoar(entries: List, remote_incident_id: str):
    demisto.debug(f"Reopen incident '{remote_incident_id}'")
    entries.append(
        {
            "Type": EntryType.NOTE,
            "Contents": {
                "dbotIncidentReopen": True,
            },
            "ContentsFormat": EntryFormat.JSON,
        }
    )


def set_xsoar_entries(
    updated_object: dict[str, Any],
    entries: list,
    remote_incident_id: str,
    incident_type_name: str,
) -> None:
    if demisto.params().get("close_incident"):
        incident_status: Optional[str] = updated_object.get("status")
        if incident_status == "Closed":
            close_in_xsoar(entries, remote_incident_id, incident_type_name)
        # the 'Closed' status as been checked right before, no need to
        # exclude it from STATUS_XSOAR_TO_HFL's values
        elif incident_status in STATUS_XSOAR_TO_HFL:
            reopen_in_xsoar(entries, remote_incident_id)


def set_xsoar_security_events_entries(
    updated_object: dict[str, Any],
    entries: list,
    remote_incident_id: str,
):
    set_xsoar_entries(updated_object, entries, remote_incident_id, "Hurukai alert")


def set_xsoar_threats_entries(
    updated_object: dict[str, Any],
    entries: list,
    remote_incident_id: str,
):
    set_xsoar_entries(updated_object, entries, remote_incident_id, "Hurukai threat")


def get_remote_data(
    client: Client,
    args: dict[str, Any],
) -> GetRemoteDataResponse:
    """Mirror modifications from remote EDR instance into XSOAR.

    Args:
        client: Demisto client to use. Initialized in the 'main' function.
        args:
            id: security event or threat id to retrieve.
            lastUpdate: when was the last time we retrieved data.

    Returns:
        GetRemoteDataResponse object, which contain the security event or
          threat data to update.
    """
    remote_data_args = GetRemoteDataArgs(args)
    remote_incident_id: str = remote_data_args.remote_incident_id

    incident_type: str  # check 'IncidentType' for valid values
    incident_id: str

    # the 'remote_incident_id' format is define in the 'get_modified_remote_data'
    # function ('sec:XXX' or 'thr:YYY')
    incident_type, incident_id = remote_incident_id.split(":", 1)

    mirrored_data: dict[str, Any]
    updated_object: dict[str, Any]

    entries: list[dict] = []

    match incident_type:

        case IncidentType.SECURITY_EVENT:
            _get_remote_data = get_remote_secevent_data
            _set_xsoar_entries = set_xsoar_security_events_entries

        case IncidentType.THREAT:
            _get_remote_data = get_remote_threat_data
            _set_xsoar_entries = set_xsoar_threats_entries

        case _:
            raise ValueError(
                f"Expected '{IncidentType.SECURITY_EVENT}' or '{IncidentType.THREAT}' "
                f"for 'incident_type', get '{incident_type}' ({remote_incident_id})"
            )

    mirrored_data, updated_object = _get_remote_data(client, incident_id)

    if updated_object:
        demisto.debug(
            f"Update incident {remote_incident_id} with fields: {updated_object}"
        )
        _set_xsoar_entries(updated_object, entries, remote_incident_id)

    else:
        # log it as error because in this function we expect an update
        # from remote the instance
        demisto.error(f"No update found for incident {remote_incident_id}")

    return GetRemoteDataResponse(
        mirrored_object=updated_object,
        entries=entries,
    )


def close_in_hfl(delta: dict[str, Any]) -> bool:
    """
    Closing in the remote system should happen only when both:
        1. The user asked for it
        2. One of the closing fields appears in the delta

    The second condition is here to avoid to continuously send a closing request
    on incidents that are already closed but have to be updated (e.g.: update of
    the description or comment).
    """
    closing_fields = {"closeReason", "closingUserId", "closeNotes"}
    return demisto.params().get("close_in_hfl") and bool(closing_fields & set(delta))


def update_remote_incident(
    delta: dict[str, Any],
    incident_status: IncidentStatus,
    incident_type: str,
    incident_id: str,
    *,
    change_incident_status_fn: Callable[[str, str], Any],
) -> None:

    new_remote_status: Optional[str] = None

    match incident_status:

        case IncidentStatus.PENDING:
            new_remote_status = "new"

        case IncidentStatus.ACTIVE:
            new_remote_status = "investigating"

        case IncidentStatus.DONE:
            if close_in_hfl(delta):
                new_remote_status = "closed"

        case IncidentStatus.ARCHIVE:
            demisto.debug(
                "The 'ARCHIVE' status is not supported on HarfangLab EDR side"
            )

        case _:
            raise ValueError(
                f"Expected one of the IncidentStatus' values from "
                f"'CommonServerPython.py' for 'incident_status', get "
                f"'{incident_status}' ({incident_type}:{incident_id})"
            )

    if new_remote_status:

        if new_remote_status not in SECURITY_EVENT_STATUS:
            raise ValueError(
                f"Invalid value for 'new_remote_status': "
                f"expected one of {SECURITY_EVENT_STATUS}, get '{new_remote_status}'"
            )

        demisto.debug(
            f"Incident '{incident_type}:{incident_id}', will have its status "
            f"changed to '{new_remote_status}'"
        )

        change_incident_status_fn(incident_id, new_remote_status)


def update_remote_security_event(
    client: Client,
    delta: dict[str, Any],
    incident_status: IncidentStatus,
    incident_type: str,
    incident_id: str,
) -> None:

    update_remote_incident(
        delta,
        incident_status,
        incident_type,
        incident_id,
        change_incident_status_fn=client.change_security_event_status,
    )


def update_remote_threat(
    client: Client,
    delta: dict[str, Any],
    incident_status: IncidentStatus,
    incident_type: str,
    incident_id: str,
) -> None:

    if "details" in delta:
        client.update_threat_description(incident_id, delta["details"])

    update_remote_incident(
        delta,
        incident_status,
        incident_type,
        incident_id,
        change_incident_status_fn=client.change_threat_status,
    )


def update_remote_system(client: Client, args: dict[str, Any]) -> str:
    """
    Mirrors local changes from XSOAR to the remote EDR instance.

    Args:
        client: Demisto client to use. Initialized in the 'main' function.
        args: A dictionary containing the data regarding a modified incident, including:
          data, entries, incident_changed, remote_incident_id, inc_status, delta

    Returns:
        The remote incident id that was modified. This is important when the
        incident is newly created remotely.
    """
    update_remote_system_args = UpdateRemoteSystemArgs(args)

    delta: Optional[dict[str, Any]] = update_remote_system_args.delta

    incident_has_changed: bool = update_remote_system_args.incident_changed
    incident_status: IncidentStatus = update_remote_system_args.inc_status

    remote_incident_id: str = update_remote_system_args.remote_incident_id

    incident_type: str
    incident_id: str

    # the 'remote_incident_id' format is define in the 'get_modified_remote_data'
    # function ('sec:XXX' or 'thr:YYY')
    incident_type, incident_id = remote_incident_id.split(":", 1)

    match incident_type:

        case IncidentType.SECURITY_EVENT:
            _update_remote_incident = update_remote_security_event

        case IncidentType.THREAT:
            _update_remote_incident = update_remote_threat

        case _:
            raise ValueError(
                f"Expected '{IncidentType.SECURITY_EVENT}' or '{IncidentType.THREAT}' "
                f"for 'incident_type', get '{incident_type}' ({remote_incident_id})"
            )

    if incident_has_changed:
        if delta:

            demisto.debug(
                f"The following fields has been changed for incident "
                f"'{remote_incident_id}': {delta.items()}"
            )

            _update_remote_incident(
                client,
                delta,
                incident_status,
                incident_type,
                incident_id,
            )

            demisto.debug(f"Incident '{remote_incident_id}' successfully updated")

        else:
            demisto.error(
                f"Incident '{remote_incident_id}' is marked as changed, "
                f"but have no delta"
            )
    else:
        demisto.debug(f"No change found for incident '{remote_incident_id}'")

    return remote_incident_id


def get_mapping_fields(client, args) -> GetMappingFieldsResponse:
    """
    Returns the list of fields to map in outgoing mirroring, for incidents and detections.
    """

    demisto.debug("In get_mapping_fields")
    mapping_response = GetMappingFieldsResponse()

    security_event_type_scheme = SchemeTypeMapping(
        type_name="HarfangLab EDR Security Event"
    )
    for argument, description in HFL_SECURITY_EVENT_OUTGOING_ARGS.items():
        security_event_type_scheme.add_field(name=argument, description=description)
    mapping_response.add_scheme_type(security_event_type_scheme)

    threat_type_scheme = SchemeTypeMapping(type_name="HarfangLab EDR Threat")
    for argument, description in HFL_THREAT_OUTGOING_ARGS.items():
        threat_type_scheme.add_field(name=argument, description=description)
    mapping_response.add_scheme_type(threat_type_scheme)

    return mapping_response


def main() -> None:

    # keys in "integration_params" are granted to be present (no need to use dict.get())
    # but the value can still be null/empty
    integration_params: dict[str, Any] = demisto.params()

    command: str = demisto.command()
    command_arguments: dict[str, Any] = demisto.args()

    verify: bool = not integration_params["insecure"]
    proxy: bool = integration_params["proxy"]

    base_url: str = integration_params["url"].rstrip("/").strip()
    api_token: str = integration_params["credentials"]["password"]

    if not api_token:
        api_token = integration_params["apikey"]

    headers: dict[str, str] = {"Authorization": f"Token {api_token}"}

    try:
        client = Client(base_url, verify=verify, proxy=proxy, headers=headers)
    except Exception as error:
        raise RuntimeError("fail to instantiate the client") from error

    try:
        target_function: Callable[..., Any] = get_function_from_command_name(command)
    except KeyError:
        raise ValueError(f"unknown command: {command}")

    if command == "fetch-incidents":

        command_arguments["last_run"] = get_last_run()

        for fetch_arg in (
            "alert_status",
            "alert_type",
            "fetch_types",
            "first_fetch",
            "max_fetch",
            "min_severity",
            "mirror_direction",
        ):
            command_arguments[fetch_arg] = integration_params.get(fetch_arg)

    try:
        result: Any = target_function(client, command_arguments)
    except Exception as error:
        return_error(f"Fail to execute command '{command}'")
        raise RuntimeError from error  # semantic purpose, should never effectively happen

    if command == "fetch-incidents":
        demisto.setLastRun(result[0])  # result[0] -> last_run object as dict
        demisto.incidents(result[1])  # result[1] -> incidents list

    return_results(result)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
