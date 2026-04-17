import html
import json
import re
import traceback
from datetime import datetime
from urllib.parse import quote

from functools import reduce

from typing import Any
from collections.abc import Callable

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

""" CONSTANTS """
# disable-secrets-detection-start
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
FEED_URL = "https://api.intel471.com/v1"
FEED_URL_VERITY471 = "https://api.intel471.cloud"
TITAN_PORTAL_URL = "https://titan.intel471.com/"
VERITY471_PORTAL_URL = "https://titan.intel471.com/"
MAX_INCIDENTS_TO_FETCH = 100
INTEL471_SEVERITIES = ["Low", "Medium", "High", "Critical"]
INCIDENT_TYPE = "Intel 471 Watcher Alert"
DEMISTO_VERSION = demisto.demistoVersion()
CONTENT_PACK = f"Intel471 Feed/{get_pack_version()!s}"
INTEGRATION = "Intel471 Watcher Alerts"
USER_AGENT = f'XSOAR/{DEMISTO_VERSION["version"]}.{DEMISTO_VERSION["buildNumber"]} - {CONTENT_PACK} - {INTEGRATION}'
TAG_RE = re.compile(r"<[^>]+>")
# disable-secrets-detection-end

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def search_alerts_titan(
        self,
        watcher_group_uids: str | None,
        max_results: int | None,
        start_time: int | None,
        last_alert_uid: str | None,
    ) -> dict:
        """Searches for Intel 471 Watcher Alerts using the '/get_alerts' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type watcher_group_uids: ``Optional[str]``
        :param watcher_group_uids: the uid(s) of the watcher group(s) for which alerts should be fetched

        :type max_results: ``Optional[int]``
        :param max_results: maximum number of results to return

        :type start_time: ``Optional[int]``
        :param start_time: start timestamp (epoch in seconds) for the alert search

        :type last_alert_uid: ``Optional[str]``
        : param last_alert_uid: uid of the most recent alert already acquired

        :return: Dict containing the found Intel 471 Watcher alerts
        :rtype: ``Dict``
        """

        request_params: dict[str, Any] = {}

        request_params["showRead"] = "true"
        request_params["displayWatchers"] = "true"
        request_params["markAsRead"] = "false"
        request_params["sort"] = "earliest"

        if watcher_group_uids:
            for watcher_group_uid in watcher_group_uids.replace(" ", "").split(","):
                request_params["watcherGroup"] = watcher_group_uid

        if max_results:
            request_params["count"] = max_results

        # Only need to set a from timestamp if no last alert uid is set.
        if last_alert_uid:
            request_params["offset"] = last_alert_uid
        else:
            if start_time:
                request_params["from"] = start_time

        return self._http_request(method="GET", url_suffix="/alerts", auth=self._auth, params=request_params)

    def search_alerts_verity471(
        self,
        watcher_group_uids: str | None,
        max_results: int | None,
        start_time: int | None,
        last_cursor: str | None,
    ) -> dict:
        """Searches for Intel 471 Watcher Alerts using the '/get_alerts' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type watcher_group_uids: ``Optional[str]``
        :param watcher_group_uids: the uid(s) of the watcher group(s) for which alerts should be fetched

        :type max_results: ``Optional[int]``
        :param max_results: maximum number of results to return

        :type start_time: ``Optional[int]``
        :param start_time: start timestamp (epoch in seconds) for the alert search

        :type last_cursor: ``Optional[str]``
        : param last_cursor: the most recent cursor received from last query

        :return: Dict containing the found Intel 471 Watcher alerts
        :rtype: ``Dict``
        """

        request_params: dict[str, Any] = {}

        if watcher_group_uids:
            demisto.debug(f"watcher_group_ids: {watcher_group_uids}")
            request_params["watcher_group_ids"] = watcher_group_uids

        if max_results:
            request_params["size"] = max_results

        if start_time:
            request_params["from"] = start_time

        if last_cursor:
            request_params["cursor"] = last_cursor

        return self._http_request(
            method="GET", url_suffix="/integrations/watchers/v1/alerts/stream", auth=self._auth, params=request_params
        )

    def search_alert_details_verity471(
        self,
        alert_url,
    ) -> dict:
        """Fetches a single Verity alert document from the given API URL.

        Sends an HTTP GET to ``alert_url`` (typically ``links.verity_api.href`` on an alert). No path
        suffix is appended; the full URL is used as-is.

        :type alert_url: ``str``
        :param alert_url: Absolute Verity API URL for the alert detail resource.

        :return: Dict containing the JSON body returned for that alert document.
        :rtype: ``Dict``
        """
        response = self._http_request(method="GET", full_url=alert_url, auth=self._auth)
        return response

    def search_watcher_group_details_verity471(
        self,
        watcher_group_id: str,
    ) -> dict:
        """Fetches watcher group records from the Verity watchers API.

        GET ``/integrations/watchers/v1/watcher-groups`` with ``watcher_group_id`` supplied as a query
        parameter.

        :type watcher_group_id: ``str``
        :param watcher_group_id: Watcher group identifier used to filter the response.

        :return: Dict containing the API JSON response (watcher group list or envelope).
        :rtype: ``Dict``
        """
        params = {"watcher_group_id": watcher_group_id}
        response = self._http_request(
            method="GET",
            full_url="https://api.intel471.cloud/integrations/watchers/v1/watcher-groups",
            auth=self._auth,
            params=params,
        )
        return response

    def search_watcher_details_verity471(
        self,
        watcher_id: str,
    ) -> dict:
        """Fetches watcher records from the Verity watchers API.

        GET ``/integrations/watchers/v1/watchers`` with ``watcher_id`` supplied as a query parameter.

        :type watcher_id: ``str``
        :param watcher_id: Watcher identifier used to filter the response.

        :return: Dict containing the API JSON response (watcher list or envelope).
        :rtype: ``Dict``
        """
        params = {"watcher_id": watcher_id}
        response = self._http_request(
            method="GET", full_url="https://api.intel471.cloud/integrations/watchers/v1/watchers", auth=self._auth, params=params
        )

        return response


""" HELPER FUNCTIONS """


def convert_to_demisto_severity(severity: str) -> int:
    """Maps Intel 471 severity to Cortex XSOAR severity

    Converts the Intel 471 alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Intel 471 API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        "Low": IncidentSeverity.LOW,
        "Medium": IncidentSeverity.MEDIUM,
        "High": IncidentSeverity.HIGH,
        "Critical": IncidentSeverity.CRITICAL,
    }[severity]


def remove_tags(html: str) -> str:
    return TAG_RE.sub("", html)


def deep_get(dictionary, path, default: Any) -> Any:
    result: Any

    keys = path.split(".")
    value = reduce(lambda d, key: d[int(key)] if isinstance(d, list) else d.get(key) if d else default, keys, dictionary)
    if value:
        result = value
    else:
        result = default

    return result


def _parse_iso8601_datetime(value: str) -> datetime:
    """Parse ISO-8601 datetimes using stdlib only (common subset of dateutil.parser.isoparse)."""
    s = value.strip()
    if len(s) > 10 and s[10] == " ":
        s = s[:10] + "T" + s[11:]
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def as_timestamp(datetime_str: str) -> int:
    if not datetime_str:
        return 0
    ts = _parse_iso8601_datetime(datetime_str)
    return int(ts.timestamp() * 1000)


class FlattenedJSON:
    def __init__(
        self,
        data: dict[str, Any],
        include_keys: Set[str] | None = None,
        exclude_keys: Set[str] | None = None,
        key_predicate: Callable[[str, Any], bool] | None = None,
        include_subtrees: Set[str] | None = None,
        exclude_subtrees: Set[str] | None = None,
        regex: bool = False,
        missing_sentinel: Any | None = None,
    ):
        """
        :param data: input JSON (already parsed to dict)
        :param include_keys: include only matching leaf paths
        :param exclude_keys: exclude matching leaf paths
        :param key_predicate: custom function (path, value) -> bool
        :param include_subtrees: include entire subtrees
        :param exclude_subtrees: exclude entire subtrees
        :param regex: treat patterns as regex
        :param missing_sentinel: value used when encountering None or missing values
        """
        self._data = data
        self._flattened: dict[str, Any] = {}

        self.include_keys = include_keys
        self.exclude_keys = exclude_keys
        self.include_subtrees = include_subtrees
        self.exclude_subtrees = exclude_subtrees
        self.key_predicate = key_predicate
        self.regex = regex
        self.missing_sentinel = missing_sentinel

        self._flatten(self._data)

    def _match(self, path: str, patterns: Set[str] | None) -> bool:
        if not patterns:
            return False
        if self.regex:
            return any(re.search(p, path) for p in patterns)
        return any(p in path for p in patterns)

    def _should_skip_subtree(self, path: str) -> bool:
        return self._match(path, self.exclude_subtrees)

    def _should_force_include_subtree(self, path: str) -> bool:
        return self._match(path, self.include_subtrees)

    def _should_include_leaf(self, path: str, value: Any) -> bool:
        if self.key_predicate is not None:
            return self.key_predicate(path, value)

        if self.include_keys and not self._match(path, self.include_keys):
            return False

        return not (self.exclude_keys and self._match(path, self.exclude_keys))

    def _apply_sentinel(self, value: Any) -> Any:
        if value is None and self.missing_sentinel is not None:
            return self.missing_sentinel
        return value

    def _flatten(self, obj: Any, parent_key: str = ""):
        if parent_key and self._should_skip_subtree(parent_key):
            return

        force_include = parent_key and self._should_force_include_subtree(parent_key)

        if isinstance(obj, dict):
            for key, value in obj.items():
                new_key = f"{parent_key}.{key}" if parent_key else key
                self._flatten(value, new_key)

        elif isinstance(obj, list):
            if all(not isinstance(item, (dict | list)) for item in obj):
                if parent_key and (force_include or self._should_include_leaf(parent_key, obj)):
                    processed = [self._apply_sentinel(v) for v in obj]
                    self._flattened[parent_key] = ", ".join(map(str, processed))
            else:
                for idx, item in enumerate(obj):
                    new_key = f"{parent_key}[{idx}]"
                    self._flatten(item, new_key)

        else:
            if parent_key and (force_include or self._should_include_leaf(parent_key, obj)):
                self._flattened[parent_key] = self._apply_sentinel(obj)

    def __str__(self) -> str:
        return "\n".join(f"{k} - {v}" for k, v in self._flattened.items())

    def to_dict(self) -> dict[str, Any]:
        return self._flattened


""" TITAN BACKEND HELPERS """


def get_report_type(url: str) -> str:
    report_type = "REPORT:\n"

    if "inforep" in url:
        report_type = "INFO REPORT:\n"
    elif "fintel" in url:
        report_type = "FINTEL:\n"
    elif "spotrep" in url:
        report_type = "SPOT REPORT:\n"

    return report_type


def compose_incident_title(alert: dict) -> str:
    title: str = ""

    if alert.get("actor", None):
        title = "ACTOR:\n"
        handles: list = alert.get("actor", {}).get("handles", [])
        if handles:
            title += ",".join(handles)
    elif alert.get("breachAlert", None):
        title = "BREACH ALERT:\n" + deep_get(alert, "breachAlert.data.breach_alert.title", "")
    elif alert.get("credential", None):
        title = "CREDENTIAL:\n" + deep_get(alert, "credential.data.credential_login", "")
    elif alert.get("credential_occurrence", None):
        title = "CREDENTIAL OCCURRENCE:\n" + deep_get(alert, "credential_occurrence.data.credential.credential_login", "")
    elif alert.get("credential_set", None):
        title = "CREDENTIAL SET:\n" + deep_get(alert, "credential_set.data.name", "")
    elif alert.get("cveReport", None):
        title = "CVE REPORT:\n" + deep_get(alert, "cveReport.data.cve_report.name", "")
    elif alert.get("entity", None):
        title = "ENTITY:\n" + deep_get(alert, "entity.value", "")
    elif alert.get("event", None):
        title = (
            "MALWARE EVENT:\n"
            + deep_get(alert, "event.data.threat.data.family", "")
            + " - "
            + deep_get(alert, "event.data.event_type", "")
        )
    elif alert.get("indicator", None):
        title = (
            "MALWARE INDICATOR:\n"
            + deep_get(alert, "indicator.data.threat.data.family", "")
            + " - "
            + deep_get(alert, "indicator.data.context.description", "")
        )
    elif alert.get("instantMessage", None):
        title = "INSTANT MESSAGE:\n" + html.unescape(
            " ".join(remove_tags(deep_get(alert, "instantMessage.data.message.text", "")).strip().split())[:100]
        )
    elif alert.get("ioc", None):
        title = "IOC:\n" + deep_get(alert, "ioc.value", "")
    elif alert.get("post", None):
        title = "FORUM POST:\n" + html.unescape(" ".join(remove_tags(deep_get(alert, "post.message", "")).strip().split())[:100])
    elif alert.get("data_leak_post", None):
        title = "DATA LEAK POST:\n" + html.unescape(
            " ".join(remove_tags(deep_get(alert, "data_leak_post.links.thread.title", "")).strip().split())[:100]
        )
    elif alert.get("report", None):
        title = get_report_type(deep_get(alert, "report.portalReportUrl", "")) + deep_get(alert, "report.subject", "")
    elif alert.get("spotReport", None):
        title = "SPOT REPORT:\n" + deep_get(alert, "spotReport.data.spot_report.spot_report_data.title", "")
    else:
        title = "UNKNOWN ALERT TYPE:\n" + "UID: " + alert.get("uid", "")

    return title


def compose_titan_url(alert: dict) -> str:
    titan_url: str = ""

    if alert.get("actor", None):
        handles: list = alert.get("actor", {}).get("handles", [])
        if handles:
            titan_url = TITAN_PORTAL_URL + "search/Actor:" + handles[0] + "/actors?ordering=latest&period_of_time=all"
    elif alert.get("breachAlert", None):
        titan_url = TITAN_PORTAL_URL + "report/breach_alert/" + deep_get(alert, "breachAlert.uid", "")
    elif alert.get("credential", None):
        titan_url = TITAN_PORTAL_URL + "credential/" + deep_get(alert, "credential.uid", "")
    elif alert.get("credential_occurrence", None):
        titan_url = TITAN_PORTAL_URL + "credential/" + deep_get(alert, "credential_occurrence.data.credential.uid", "")
    elif alert.get("credential_set", None):
        titan_url = TITAN_PORTAL_URL + "credential_set/" + deep_get(alert, "credential_set.uid", "")
    elif alert.get("cveReport", None):
        titan_url = TITAN_PORTAL_URL + "report/cve/" + deep_get(alert, "cveReport.uid", "")
    elif alert.get("entity", None):
        titan_url = TITAN_PORTAL_URL
    elif alert.get("event", None):
        titan_url = TITAN_PORTAL_URL + "malware/event/" + deep_get(alert, "event.uid", "")
    elif alert.get("indicator", None):
        titan_url = TITAN_PORTAL_URL + "malware/indicator/" + deep_get(alert, "indicator.data.uid", "")
    elif alert.get("instantMessage", None):
        thread_uid_instant_message: str = deep_get(alert, "instantMessage.data.channel.uid", "")
        message_uid: str = deep_get(alert, "instantMessage.data.message.uid", "")
        titan_url = TITAN_PORTAL_URL + "ims_thread/" + thread_uid_instant_message + "?message_uid=" + message_uid
    elif alert.get("ioc", None):
        titan_url = (
            TITAN_PORTAL_URL + "search/IOC%7C*:" + deep_get(alert, "ioc.value", "") + "?ordering=latest&period_of_time=all"
        )
    elif alert.get("post", None):
        thread_uid_post: str = deep_get(alert, "post.links.thread.uid", "")
        post_uid: str = deep_get(alert, "post.uid", "")
        titan_url = TITAN_PORTAL_URL + "post_thread/" + thread_uid_post + "?post_uid=" + post_uid
    elif alert.get("data_leak_post", None):
        data_leak_post_uid: str = deep_get(alert, "uid", "")
        titan_url = TITAN_PORTAL_URL + "data_leak_thread/" + data_leak_post_uid
    elif alert.get("report", None):
        titan_url = deep_get(alert, "report.portalReportUrl", "")
    elif alert.get("spotReport", None):
        titan_url = TITAN_PORTAL_URL + "report/spotrep/" + deep_get(alert, "spotReport.data.spot_report.uid", "")
    else:
        titan_url = TITAN_PORTAL_URL

    return titan_url


def compose_incident_watcher_details(alert: dict, watcher_groups: list) -> tuple[str, str]:
    watcher_group_description: str = ""
    watcher_group_uid = alert.get("watcherGroupUid", None)
    watcher_group: dict = [wg for wg in watcher_groups if wg["uid"] == watcher_group_uid][0]
    if watcher_group:
        watcher_group_description = watcher_group.get("name", "")

    watcher_description: str = ""
    watcher_uid: str = alert.get("watcherUid", "")
    watchers: list = []
    if watcher_group.get("watchers", None):
        watchers = watcher_group.get("watchers", [])
        watcher: dict = [w for w in watchers if w["uid"] == watcher_uid][0]
        if watcher:
            watcher_description = watcher.get("description", "")

    return watcher_group_description, watcher_description


def compose_incident_details(alert: dict, watcher_groups: list) -> str:
    details: str = ""

    if alert.get("actor", None):
        details += "Source Object: ACTOR"
        details += "\n\n" + "Actor Details:"
        actor_details: dict = deep_get(alert, "actor.links", {})
        actor_details_str: str = json.dumps(actor_details, indent=2, sort_keys=False)
        details += "\n" + actor_details_str
    elif alert.get("breachAlert", None):
        details += "Source Object: BREACH ALERT"
        details += "\n" + "Title: " + deep_get(alert, "breachAlert.data.breach_alert.title", "")
        details += (
            "\n"
            + "Confidence: "
            + deep_get(alert, "breachAlert.data.breach_alert.confidence.level", "")
            + " ("
            + deep_get(alert, "breachAlert.data.breach_alert.confidence.description", "")
            + ")"
        )
        details += "\n" + "Actor/Group: " + deep_get(alert, "breachAlert.data.breach_alert.actor_or_group", "")
        details += "\n\n" + "Victim Details:"
        victim_details: dict = deep_get(alert, "breachAlert.data.breach_alert.victim", {})
        victim_details_str: str = json.dumps(victim_details, indent=2, sort_keys=False)
        details += "/n" + victim_details_str
    elif alert.get("credential", None):
        details += "Source Object: CREDENTIAL"
        details += "\n" + "Credential Login: " + deep_get(alert, "credential.data.credential_login", "")
        details += "\n" + "Detection Domain: " + deep_get(alert, "credential.data.detection_domain", "")
        details += "\n" + "Password Strength: " + deep_get(alert, "credential.data.password.strength", "")
        affiliations_list_credential: list = alert.get("credential", {}).get("data", {}).get("affiliations", [])
        affiliations_credential: str = ",".join(affiliations_list_credential)
        details += "\n" + "Affiliations: " + affiliations_credential
    elif alert.get("credential_occurrence", None):
        details += "Source Object: CREDENTIAL OCCURRENCE"
        details += "\n" + "Credential Login: " + deep_get(alert, "credential_occurrence.data.credential.credential_login", "")
        details += "\n" + "Detection Domain: " + deep_get(alert, "credential_occurrence.data.credential.detection_domain", "")
        details += "\n" + "Password Strength: " + deep_get(alert, "credential_occurrence.data.credential.password.strength", "")
        affiliations_list_credential_occurrence: list = (
            alert.get("credential_occurrence", {}).get("data", {}).get("credential", {}).get("affiliations", [])
        )
        affiliations_credential_occurrence: str = ",".join(affiliations_list_credential_occurrence)
        details += "\n" + "Affiliations: " + affiliations_credential_occurrence
        details += "\n" + "Credential Set: " + deep_get(alert, "credential_occurrence.data.credential_set.name", "")
    elif alert.get("credential_set", None):
        details += "Source Object: CREDENTIAL SET"
        details += "\n" + "Name: " + deep_get(alert, "credential_set.data.name", "")
        details += "\n\n" + html.unescape(" ".join(remove_tags(str(alert)).strip().split()))
    elif alert.get("cveReport", None):
        details += "Source Object: CVE REPORT"
        details += "\n" + "CVE: " + deep_get(alert, "cveReport.data.cve_report.name", "")
        details += "\n" + "Risk Level: " + deep_get(alert, "cveReport.data.cve_report.risk_level", "")
        details += "\n" + "Vendor: " + deep_get(alert, "cveReport.data.cve_report.vendor_name", "")
        details += "\n" + "Product: " + deep_get(alert, "cveReport.data.cve_report.product_name", "")
        details += (
            "\n" + "Exploit Available: " + str(deep_get(alert, "cveReport.data.cve_report.exploit_status.available", "False"))
        )
        details += (
            "\n" + "Exploit Weaponized: " + str(deep_get(alert, "cveReport.data.cve_report.exploit_status.weaponized", "False"))
        )
        details += (
            "\n" + "Exploit Productized: " + str(deep_get(alert, "cveReport.data.cve_report.exploit_status.productized", "False"))
        )
        details += "\n" + "Patch Status: " + str(deep_get(alert, "cveReport.data.cve_report.patch_status", ""))
        details += "\n" + "Countermeasures: " + str(deep_get(alert, "cveReport.data.cve_report.counter_measures", ""))
        details += "\n\n" + "Summary: " + deep_get(alert, "cveReport.data.cve_report.summary", "")
    elif alert.get("entity", None):
        details += "Source Object: ENTITY"
        details += "\n" + "Entity: " + deep_get(alert, "entity.value", "")
        details += "\n\n" + html.unescape(" ".join(remove_tags(str(alert)).strip().split()))
    elif alert.get("event", None):
        details += "Source Object: MALWARE EVENT"
        details += "\n" + "Malware Family: " + deep_get(alert, "event.data.threat.data.family", "")
        details += "\n" + "Malware Family Version: " + deep_get(alert, "event.data.threat.data.version", "")
        details += "\n" + "Mitre Tactics: " + deep_get(alert, "event.data.mitre_tactics", "")
        details += "\n" + "Event Type: " + deep_get(alert, "event.data.event_type", "")
        details += "\n\n" + "Event Details:"
        event_details: dict = deep_get(alert, "event.data.event_data", "")
        event_details_str: str = json.dumps(event_details, indent=2, sort_keys=False)
        details += "\n" + event_details_str
    elif alert.get("indicator", None):
        details += "Source Object: MALWARE INDICATOR"
        details += "\n" + "Malware Family: " + deep_get(alert, "indicator.data.threat.data.family", "")
        details += "\n" + "Malware Family Version: " + deep_get(alert, "indicator.data.threat.data.version", "")
        details += "\n" + "Context: " + deep_get(alert, "indicator.data.context.description", "")
        details += "\n" + "Mitre Tactics: " + deep_get(alert, "indicator.data.mitre_tactics", "")
        details += "\n" + "Confidence Level: " + deep_get(alert, "indicator.data.confidence", "")
        details += "\n" + "Indicator Type: " + deep_get(alert, "indicator.data.indicator_type", "")
        details += "\n\n" + "Indicator Details:"
        indicator_details: dict = deep_get(alert, "indicator.data.indicator_data", "")
        indicator_details_str: str = json.dumps(indicator_details, indent=2, sort_keys=False)
        details += "\n" + indicator_details_str
    elif alert.get("instantMessage", None):
        details += "Source Object: INSTANT MESSAGE"
        details += "\n" + "Service: " + deep_get(alert, "instantMessage.data.server.service_type", "")
        details += "\n" + "Channel: " + deep_get(alert, "instantMessage.data.channel.name", "")
        details += "\n" + "Actor: " + deep_get(alert, "instantMessage.data.actor.handle", "")
        details += "\n\n" + html.unescape(
            " ".join(remove_tags(deep_get(alert, "instantMessage.data.message.text", "")).strip().split())
        )
    elif alert.get("ioc", None):
        details += "Source Object: IOC"
        details += "\n" + "Type: " + deep_get(alert, "ioc.type", "")
        details += "\n" + "IOC: " + deep_get(alert, "ioc.value", "")
    elif alert.get("post", None):
        details += "Source Object: FORUM POST"
        details += "\n" + "Forum: " + deep_get(alert, "post.links.forum.name", "")
        details += "\n" + "Thread Topic: " + deep_get(alert, "post.links.thread.topic", "")
        details += "\n" + "Actor: " + deep_get(alert, "post.links.authorActor.handle", "")
        details += "\n\n" + html.unescape(" ".join(remove_tags(deep_get(alert, "post.message", "")).strip().split()))
    elif alert.get("data_leak_post", None):
        details += "Source Object: DATA LEAK POST"
        details += "\n" + "Website: " + deep_get(alert, "data_leak_post.links.blog.name", "")
        details += "\n" + "Thread Topic: " + deep_get(alert, "data_leak_post.links.thread.topic", "")
        details += (
            "\n"
            + "Message: "
            + html.unescape(" ".join(remove_tags(deep_get(alert, "data_leak_post.message", "")).strip().split()))
        )
        details += "\n" + "File listing: " + deep_get(alert, "data_leak_post.links.thread.topic", "")
        details += "\n\n" + html.unescape(" ".join(remove_tags(json.dumps(alert, indent=2)).strip().split()))
    elif alert.get("report", None):
        details += "Source Object: " + get_report_type(deep_get(alert, "report.portalReportUrl", ""))
        details += "Source Characterization " + deep_get(alert, "report.sourceCharacterization", "")
        details += "\n\n" + "Subject: " + deep_get(alert, "report.subject", "")
    elif alert.get("spotReport", None):
        details += "Source Object: SPOT REPORT"
        details += "\n\n" + deep_get(alert, "spotReport.data.spot_report.spot_report_data.text", "")
        purported_victims_details: dict = deep_get(alert, "spotReport.data.spot_report.spot_report_data.victims", "")
        if purported_victims_details:
            purported_victims_details_str: str = json.dumps(purported_victims_details, indent=2, sort_keys=False)
            details += "\n\n" + "Purported Victims:"
            details += "\n" + purported_victims_details_str
    else:
        details += "Source Object: UNKNOWN ALERT TYPE"
        details += "\n\n" + html.unescape(" ".join(remove_tags(str(alert)).strip().split()))

    return details


""" VERITY471 BACKEND HELPERS """

# Schemas under test_data/fixtures/*.json — detail responses are single list items (flat / Verity-native keys).


def _verity_malware_family(alert: dict) -> str:
    return str(deep_get(alert, "threat.data.malware.family", "") or deep_get(alert, "threat.data.malware_family.name", "") or "")


def _verity_malware_version(alert: dict) -> str:
    return str(deep_get(alert, "threat.data.malware.version", ""))


def _verity_indicator_display_value(alert: dict) -> str:
    """Primary human-readable value for indicators (see test_data/fixtures/malware_indicator.json)."""
    if alert.get("pattern"):
        return str(alert["pattern"])
    data = alert.get("data") or {}
    if not isinstance(data, dict):
        return ""
    return str(
        data.get("domain")
        or deep_get(data, "ipv4.ip_address", None)
        or data.get("url")
        or data.get("email")
        or deep_get(data, "file.sha256", None)
        or deep_get(data, "file.md5", None)
        or ""
    )


def _verity_format_sources_block(sources: Any) -> str:
    if not sources or not isinstance(sources, list):
        return ""
    parts: list[str] = []
    for i, s in enumerate(sources):
        if not isinstance(s, dict):
            parts.append(str(s))
            continue
        title = s.get("title", "")
        stype = s.get("type", "")
        sst = s.get("source_type", "")
        desc = s.get("description") or s.get("summary") or ""
        href = deep_get(s, "links.verity_api.href", "") or deep_get(s, "links.verity_portal.href", "")
        idx = s.get("index", i)
        seg = f"[{idx}] {title or '(no title)'}|type:{stype}|source_type:{sst}|href:{href}"
        if desc:
            seg += f"|desc:{desc}"
        parts.append(seg)
    return "\n".join(parts) if parts else ""


def _verity_format_assessment(assessment: Any) -> str:
    if not assessment or not isinstance(assessment, dict):
        return ""
    assessment = [f"{k.capitalize().replace('_', ' ')} - {v}" for k, v in assessment.items()]
    return "\n".join(assessment) if assessment else ""


def _verity_format_locations_block(locations: Any) -> str:
    if not locations or not isinstance(locations, list):
        return ""
    parts: list[str] = []
    for loc in locations:
        if isinstance(loc, dict):
            core = " / ".join(
                p for p in (str(loc.get("region", "")), str(loc.get("country", "")), str(loc.get("iso", ""))) if p
            ).strip()
            if loc.get("link"):
                core = f"{core} (link: {loc['link']})" if core else str(loc.get("link"))
            parts.append(core or str(loc))
        else:
            parts.append(str(loc))
    return "\n".join(parts) if parts else ""


def _verity_format_entities_block(entities: Any) -> str:
    if not entities or not isinstance(entities, list):
        return ""
    parts: list[str] = []
    for e in entities:
        if isinstance(e, dict):
            parts.append(f"[{e.get('type', '')}] {e.get('value', '')}")
        else:
            parts.append(str(e))
    return "\n".join(parts) if parts else ""


def _verity_report_body_plain(alert: dict) -> str:
    body = alert.get("body")
    if body is None:
        return ""
    return html.unescape(" ".join(remove_tags(str(body)).strip().split()))


def _verity_is_blank(value: Any) -> bool:
    """True if value should be omitted from incident details (None, '', whitespace-only, empty list/dict)."""
    if value is None:
        return True
    if isinstance(value, str):
        return len(value.strip()) == 0
    if isinstance(value, (list | dict | set | tuple)):
        return len(value) == 0
    return False


class BaseAdapter:
    """Base class for Verity471 document adapters.

    Holds the API document payload in ``alert``. Subclasses implement ``incident_name`` and
    ``incident_details``. Add shared properties or helpers on this class for all adapter types.
    """

    def __init__(self, alert: dict) -> None:
        self.alert = alert

    @property
    def alert_id(self):
        _id = (
            self.alert.get("id")
            or self.alert.get("message.id")
            or self.alert.get("post.id")
            or self.alert.get("private_message.id")
        )
        return _id


class ActorAdapter(BaseAdapter):
    """test_data/fixtures/actor.json — actors[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        title = "ACTOR:\n"
        handles: list = self.alert.get("handles", [])
        if handles:
            title += ",".join(str(h) for h in handles)
        return title

    @property
    def incident_details(self) -> str:
        details = "Source Object: ACTOR"
        details += "\n\n" + "Actor Details:"
        flattened = FlattenedJSON(self.alert)
        details += "\n" + str(flattened)
        return details


class BreachAlertAdapter(BaseAdapter):
    """test_data/fixtures/breach_alerts.json — reports[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "BREACH ALERT:\n" + str(self.alert.get("title", ""))

    @property
    def incident_details(self) -> str:
        details = "Source Object: BREACH ALERT"
        title = str(self.alert.get("title", ""))
        if not _verity_is_blank(title):
            details += "\n" + "Title: " + title
        conf = self.alert.get("confidence") or {}
        level = str(conf.get("level", ""))
        desc = str(conf.get("description", ""))
        if not _verity_is_blank(level) and not _verity_is_blank(desc):
            details += "\n" + "Confidence: " + level + " (" + desc + ")"
        elif not _verity_is_blank(level):
            details += "\n" + "Confidence: " + level
        elif not _verity_is_blank(desc):
            details += "\n" + "Confidence: (" + desc + ")"
        actor_group = str(self.alert.get("actor_or_group", ""))
        if not _verity_is_blank(actor_group):
            details += "\n" + "Actor/Group: " + actor_group
        victims = self.alert.get("victims", {})
        if not _verity_is_blank(victims):
            details += "\n\n" + "Victim Details:"
            details += "\n" + json.dumps(victims, indent=2)
        return details


class CredentialAdapter(BaseAdapter):
    """test_data/fixtures/creds_cred.json — credentials[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "CREDENTIAL:\n" + deep_get(self.alert, "data.credential_login", "")

    @property
    def incident_details(self) -> str:
        details = "Source Object: CREDENTIAL"
        login = deep_get(self.alert, "data.credential_login", "")
        if not _verity_is_blank(login):
            details += "\n" + "Credential Login: " + str(login)
        dom = deep_get(self.alert, "data.detection_domain", "")
        if not _verity_is_blank(dom):
            details += "\n" + "Detection Domain: " + str(dom)
        strength = deep_get(self.alert, "data.password.strength", "")
        if not _verity_is_blank(strength):
            details += "\n" + "Password Strength: " + str(strength)
        affiliations_list: list = (self.alert.get("data") or {}).get("affiliations", [])
        affiliations_credential: str = ",".join(str(a) for a in affiliations_list)
        if not _verity_is_blank(affiliations_credential):
            details += "\n" + "Affiliations: " + affiliations_credential
        return details


class CredentialOccurrenceAdapter(BaseAdapter):
    """test_data/fixtures/creds_cred_occurrence.json — credential_occurrences[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "CREDENTIAL OCCURRENCE:\n" + deep_get(self.alert, "data.credential.credential_login", "")

    @property
    def incident_details(self) -> str:
        details = "Source Object: CREDENTIAL OCCURRENCE"
        login = deep_get(self.alert, "data.credential.credential_login", "")
        if not _verity_is_blank(login):
            details += "\n" + "Credential Login: " + str(login)
        dom = deep_get(self.alert, "data.credential.detection_domain", "")
        if not _verity_is_blank(dom):
            details += "\n" + "Detection Domain: " + str(dom)
        strength = deep_get(self.alert, "data.credential.password.strength", "")
        if not _verity_is_blank(strength):
            details += "\n" + "Password Strength: " + str(strength)
        affiliations_list: list = (deep_get(self.alert, "data.credential", {}) or {}).get("affiliations", [])
        affiliations_str: str = ",".join(str(a) for a in affiliations_list)
        if not _verity_is_blank(affiliations_str):
            details += "\n" + "Affiliations: " + affiliations_str
        cred_set = deep_get(self.alert, "data.credential_set.name", "")
        if not _verity_is_blank(cred_set):
            details += "\n" + "Credential Set: " + str(cred_set)
        return details


class CredentialSetAdapter(BaseAdapter):
    """test_data/fixtures/creds_cred_set.json — credential_sets[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "CREDENTIAL SET:\n" + deep_get(self.alert, "data.name", "")

    @property
    def incident_details(self) -> str:
        details = "Source Object: CREDENTIAL SET"
        name = deep_get(self.alert, "data.name", "")
        if not _verity_is_blank(name):
            details += "\n" + "Name: " + str(name)
        details += "\n\n" + json.dumps(self.alert, indent=2)
        return details


class CveReportAdapter(BaseAdapter):
    """test_data/fixtures/vulnerabilities_cve.json — reports[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "CVE REPORT:\n" + str(self.alert.get("name", ""))

    @property
    def incident_details(self) -> str:
        details = "Source Object: CVE REPORT"
        name = str(self.alert.get("name", ""))
        if not _verity_is_blank(name):
            details += "\n" + "CVE: " + name
        risk = str(self.alert.get("risk_level", ""))
        if not _verity_is_blank(risk):
            details += "\n" + "Risk Level: " + risk
        vendor = str(self.alert.get("vendor_name", ""))
        if not _verity_is_blank(vendor):
            details += "\n" + "Vendor: " + vendor
        product = str(self.alert.get("product_name", ""))
        if not _verity_is_blank(product):
            details += "\n" + "Product: " + product
        es = self.alert.get("exploit_status", [])
        if not _verity_is_blank(es):
            details += "\n" + "Exploit Status: \n"
            for k in ("available", "weaponized", "productized"):
                details += f"{k.capitalize()} - {k in es}\n"
        patch = str(remove_tags(self.alert.get("patch_status", "")))
        if not _verity_is_blank(patch):
            details += "\n" + "Patch Status: " + patch
        cm = str(remove_tags(self.alert.get("counter_measures_html", "")))
        if not _verity_is_blank(cm):
            details += "\n" + "Countermeasures: " + html.unescape(cm)
        summary = str(remove_tags(self.alert.get("body", "")))
        if not _verity_is_blank(summary):
            details += "\n" + "Summary: " + summary
        return details


class EntityAdapter(BaseAdapter):
    """test_data/fixtures/malware_families.json — malware[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        label = str(self.alert.get("name") or self.alert.get("title") or "")
        return "ENTITY:\n" + label

    @property
    def incident_details(self) -> str:
        details = "Source Object: ENTITY"
        ent = str(self.alert.get("name") or self.alert.get("title", ""))
        if not _verity_is_blank(ent):
            details += "\n" + "Entity: " + ent
        details += "\n\n" + str(FlattenedJSON(self.alert, exclude_keys={"name", "title"}))
        return details


class MalwareEventAdapter(BaseAdapter):
    """test_data/fixtures/malware_event.json — events[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "MALWARE EVENT:\n" + _verity_malware_family(self.alert) + " - " + str(self.alert.get("type", ""))

    @property
    def incident_details(self) -> str:
        details = "Source Object: MALWARE EVENT"
        fam = _verity_malware_family(self.alert)
        if not _verity_is_blank(fam):
            details += "\n" + "Malware Family: " + fam
        ver = _verity_malware_version(self.alert)
        if not _verity_is_blank(ver):
            details += "\n" + "Malware Family Version: " + ver
        kc = self.alert.get("kill_chain_phases", [])
        if not _verity_is_blank(kc) and kc is not None:
            kc_str = json.dumps(kc, indent=2, sort_keys=False, default=str)
            details += "\n" + "Kill chain phases: " + kc_str
        et = str(self.alert.get("type", ""))
        if not _verity_is_blank(et):
            details += "\n" + "Event Type: " + et
        event_details = self.alert.get("data")
        block = ""
        if event_details is None:
            pass
        elif isinstance(event_details, list):
            if not _verity_is_blank(event_details):
                block = json.dumps(event_details, indent=2, sort_keys=False, default=str)
        elif isinstance(event_details, dict):
            if not _verity_is_blank(event_details):
                block = json.dumps(event_details, indent=2, sort_keys=False, default=str)
        else:
            es = str(event_details)
            if not _verity_is_blank(es):
                block = es
        if block:
            details += "\n\n" + "Event Details:"
            details += "\n" + block
        return details


class MalwareIndicatorAdapter(BaseAdapter):
    """test_data/fixtures/malware_indicator.json — indicators[] (malware / context-rich)."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "MALWARE INDICATOR:\n" + _verity_malware_family(self.alert) + " - " + str(self.alert.get("description", ""))

    @property
    def incident_details(self) -> str:
        details = "Source Object: MALWARE INDICATOR"
        fam = _verity_malware_family(self.alert)
        if not _verity_is_blank(fam):
            details += "\n" + "Malware Family: " + fam
        ver = _verity_malware_version(self.alert)
        if not _verity_is_blank(ver):
            details += "\n" + "Malware Family Version: " + ver
        desc = str(self.alert.get("description", ""))
        if not _verity_is_blank(desc):
            details += "\n" + "Description: " + desc
        kc = self.alert.get("kill_chain_phases")
        if not _verity_is_blank(kc) and kc is not None:
            kc_str = json.dumps(kc, indent=2, sort_keys=False, default=str) if isinstance(kc, list) else str(kc)
            details += "\n" + "Kill chain phases: " + kc_str
        conf = str(self.alert.get("confidence", ""))
        if not _verity_is_blank(conf):
            details += "\n" + "Confidence Level: " + conf
        itype = str(self.alert.get("type", ""))
        if not _verity_is_blank(itype):
            details += "\n" + "Indicator Type: " + itype
        ptype = str(self.alert.get("pattern_type", ""))
        if not _verity_is_blank(ptype):
            details += "\n" + "Pattern type: " + ptype
        idata = self.alert.get("data")
        block = ""
        if idata is None:
            pass
        elif isinstance(idata, list):
            if not _verity_is_blank(idata):
                block = json.dumps(idata, indent=2, sort_keys=False, default=str)
        elif isinstance(idata, dict):
            if not _verity_is_blank(idata):
                block = json.dumps(idata, indent=2, sort_keys=False, default=str)
        else:
            s = str(idata)
            if not _verity_is_blank(s):
                block = s
        if block:
            details += "\n\n" + "Indicator Details:"
            details += "\n" + block
        return details


class InstantMessageAdapter(BaseAdapter):
    """test_data/fixtures/chats_message.json — messages[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    def _message_text(self) -> str:
        return str(deep_get(self.alert, "message.text", "") or deep_get(self.alert, "message.html", "") or "")

    @property
    def incident_name(self) -> str:
        return "INSTANT MESSAGE:\n" + html.unescape(" ".join(remove_tags(self._message_text()).strip().split())[:100])

    @property
    def incident_details(self) -> str:
        details = "Source Object: INSTANT MESSAGE"
        svc = str(deep_get(self.alert, "server.type", "") or deep_get(self.alert, "server.name", ""))
        if not _verity_is_blank(svc):
            details += "\n" + "Service: " + svc
        ch = str(deep_get(self.alert, "chat_room.name", ""))
        if not _verity_is_blank(ch):
            details += "\n" + "Channel: " + ch
        act = str(deep_get(self.alert, "message.author.user_name", ""))
        if not _verity_is_blank(act):
            details += "\n" + "Actor: " + act
        msg = html.unescape(" ".join(remove_tags(self._message_text()).strip().split()))
        if not _verity_is_blank(msg):
            details += "\n\n" + msg
        return details


class ForumPostAdapter(BaseAdapter):
    """test_data/fixtures/forums_post.json — posts[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        raw = str(deep_get(self.alert, "post.message", "") or deep_get(self.alert, "post.html", ""))
        return "FORUM POST:\n" + html.unescape(" ".join(remove_tags(raw).strip().split())[:100])

    @property
    def incident_details(self) -> str:
        topic = deep_get(self.alert, "thread.topic", None)
        topic_original = deep_get(self.alert, "thread.topic_original", None)
        topic_str = str(topic or topic_original or "")
        details = "Source Object: FORUM POST"
        forum = str(deep_get(self.alert, "forum.title", ""))
        if not _verity_is_blank(forum):
            details += "\n" + "Forum: " + forum
        if not _verity_is_blank(topic_str):
            details += "\n" + "Thread Topic: " + topic_str
        actor = str(deep_get(self.alert, "post.author.user_name", ""))
        if not _verity_is_blank(actor):
            details += "\n" + "Actor: " + actor
        raw = str(deep_get(self.alert, "post.message", "") or deep_get(self.alert, "post.html", ""))
        body = html.unescape(" ".join(remove_tags(raw).strip().split()))
        if not _verity_is_blank(body):
            details += "\n\n" + body
        return details


class ForumsPrivateMessageAdapter(BaseAdapter):
    """test_data/fixtures/forums_private_message.json — private_messages[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        raw = str(deep_get(self.alert, "private_message.message", ""))
        return "FORUM PRIVATE MESSAGE:\n" + html.unescape(" ".join(remove_tags(raw).strip().split())[:100])

    @property
    def incident_details(self) -> str:
        details = "Source Object: FORUM PRIVATE MESSAGE"
        forum = str(deep_get(self.alert, "forum.title", ""))
        if not _verity_is_blank(forum):
            details += "\n" + "Forum: " + forum
        subj = str(deep_get(self.alert, "private_message.subject", ""))
        if not _verity_is_blank(subj):
            details += "\n" + "Subject: " + subj
        author = str(deep_get(self.alert, "author.user_name", ""))
        if not _verity_is_blank(author):
            details += "\n" + "Author: " + author
        raw = str(deep_get(self.alert, "private_message.message", ""))
        body = html.unescape(" ".join(remove_tags(raw).strip().split()))
        if not _verity_is_blank(body):
            details += "\n\n" + body
        return details


class FintelReportAdapter(BaseAdapter):
    """test_data/fixtures/fintel.json — reports[] (finished intelligence)."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "FINTEL:\n" + str(self.alert.get("title", ""))

    @property
    def incident_details(self) -> str:
        details = "Source Object: FINTEL"
        title = str(self.alert.get("title", ""))
        if not _verity_is_blank(title):
            details += "\n" + "Title: " + title
        t = str(self.alert.get("type", ""))
        st = str(self.alert.get("sub_type", ""))
        if not _verity_is_blank(t) or not _verity_is_blank(st):
            details += "\n" + "Type / sub_type: " + t + " / " + st
        body_plain = _verity_report_body_plain(self.alert)
        if not _verity_is_blank(body_plain):
            details += "\n\nBody:\n" + body_plain
        assessment = self.alert.get("assessment")
        if not _verity_is_blank(assessment):
            details += "\n\nAssessment:\n" + json.dumps(assessment, indent=2, sort_keys=True)
        sources = _verity_format_sources_block(self.alert.get("sources"))
        if not _verity_is_blank(sources):
            details += "\n\nSources:\n" + sources
        locations = _verity_format_locations_block(self.alert.get("locations"))
        if not _verity_is_blank(locations):
            details += "\n\nLocations:\n" + locations
        entities = _verity_format_entities_block(self.alert.get("entities"))
        if not _verity_is_blank(entities):
            details += "\n\nEntities:\n" + entities
        derived = self.alert.get("derived_entities")
        if not _verity_is_blank(derived):
            details += "\n\nDerived entities:\n" + _verity_format_entities_block(derived)
        return details


class GeopolReportAdapter(BaseAdapter):
    """test_data/fixtures/geopol_reports.json — reports[] (geopolitical intelligence)."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "GEOPOL REPORT:\n" + str(self.alert.get("title", ""))

    @property
    def incident_details(self) -> str:
        details = "Source Object: GEOPOL REPORT"
        title = str(self.alert.get("title", ""))
        if not _verity_is_blank(title):
            details += "\n" + "Title: " + title
        t = str(self.alert.get("type", ""))
        st = str(self.alert.get("sub_type", ""))
        if not _verity_is_blank(t) or not _verity_is_blank(st):
            details += "\n" + "Type / sub_type: " + t + " / " + st
        body_plain = _verity_report_body_plain(self.alert)
        if not _verity_is_blank(body_plain):
            details += "\n\nBody:\n" + body_plain
        assessment = self.alert.get("assessment")
        if not _verity_is_blank(assessment):
            details += "\n\nAssessment:\n" + json.dumps(assessment, indent=2, sort_keys=True)
        sources = _verity_format_sources_block(self.alert.get("sources"))
        if not _verity_is_blank(sources):
            details += "\n\nSources:\n" + sources
        locations = _verity_format_locations_block(self.alert.get("locations"))
        if not _verity_is_blank(locations):
            details += "\n\nLocations:\n" + locations
        entities = _verity_format_entities_block(self.alert.get("entities"))
        if not _verity_is_blank(entities):
            details += "\n\nEntities:\n" + entities
        derived = self.alert.get("derived_entities")
        if not _verity_is_blank(derived):
            details += "\n\nDerived entities:\n" + _verity_format_entities_block(derived)
        ie = self.alert.get("intelligence_estimate")
        if not _verity_is_blank(ie):
            details += "\n\nIntelligence estimate:\n"
            details += json.dumps(ie, indent=2, sort_keys=False, default=str)
        sig = self.alert.get("significant_activity")
        if not _verity_is_blank(sig):
            details += "\n\nSignificant activity:\n"
            details += json.dumps(sig, indent=2, sort_keys=False, default=str)
        return details


class InformationReportAdapter(BaseAdapter):
    """test_data/fixtures/information_reports.json — reports[] (information / info_report)."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "INFORMATION REPORT:\n" + str(self.alert.get("title", ""))

    @property
    def incident_details(self) -> str:
        details = "Source Object: INFORMATION REPORT"
        title = str(self.alert.get("title", ""))
        if not _verity_is_blank(title):
            details += "\n" + "Title: " + title
        sc = str(self.alert.get("source_characterization", ""))
        if not _verity_is_blank(sc):
            details += "\n" + "Source characterization: " + sc
        body_plain = _verity_report_body_plain(self.alert)
        if not _verity_is_blank(body_plain):
            details += "\n\nBody:\n" + body_plain
        assessment = _verity_format_assessment(self.alert.get("assessment"))
        if not _verity_is_blank(assessment):
            details += "\n\nAssessment:\n" + assessment
        sources = _verity_format_sources_block(self.alert.get("sources"))
        if not _verity_is_blank(sources):
            details += "\n\nSources:\n" + sources
        locations = _verity_format_locations_block(self.alert.get("locations"))
        if not _verity_is_blank(locations):
            details += "\n\nLocations:\n" + locations
        entities = _verity_format_entities_block(self.alert.get("entities"))
        if not _verity_is_blank(entities):
            details += "\n\nEntities:\n" + entities
        derived = self.alert.get("derived_entities")
        if not _verity_is_blank(derived):
            details += "\n\nDerived entities:\n" + _verity_format_entities_block(derived)
        return details


class MalwareReportAdapter(BaseAdapter):
    """test_data/fixtures/malware_reports.json — reports[] (malware-focused reports)."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "MALWARE REPORT:\n" + str(self.alert.get("title", ""))

    @property
    def incident_details(self) -> str:
        details = "Source Object: MALWARE REPORT"
        title = str(self.alert.get("title", ""))
        if not _verity_is_blank(title):
            details += "\n" + "Title: " + title
        rtype = str(self.alert.get("type", ""))
        if not _verity_is_blank(rtype):
            details += "\n" + "Type: " + rtype
        ver = str(self.alert.get("version", ""))
        if not _verity_is_blank(ver):
            details += "\n" + "Version: " + ver
        body_plain = _verity_report_body_plain(self.alert)
        if not _verity_is_blank(body_plain):
            details += "\n\nBody:\n" + body_plain
        assessment = self.alert.get("assessment")
        if not _verity_is_blank(assessment):
            details += "\n\nAssessment:\n" + json.dumps(assessment, indent=2, sort_keys=True)
        sources = _verity_format_sources_block(self.alert.get("sources"))
        if not _verity_is_blank(sources):
            details += "\n\nSources:\n" + sources
        locations = _verity_format_locations_block(self.alert.get("locations"))
        if not _verity_is_blank(locations):
            details += "\n\nLocations:\n" + locations
        entities = _verity_format_entities_block(self.alert.get("entities"))
        if not _verity_is_blank(entities):
            details += "\n\nEntities:\n" + entities
        derived = self.alert.get("derived_entities")
        if not _verity_is_blank(derived):
            details += "\n\nDerived entities:\n" + _verity_format_entities_block(derived)
        threat = self.alert.get("threat")
        if not _verity_is_blank(threat):
            details += "\n\nThreat:\n"
            details += json.dumps(threat, indent=2, sort_keys=False, default=str)
        return details


class SpotReportAdapter(BaseAdapter):
    """test_data/fixtures/spot_reports.json — reports[]."""

    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "SPOT REPORT:\n" + str(self.alert.get("title", ""))

    @property
    def incident_details(self) -> str:
        details = "Source Object: SPOT REPORT"
        body = str(self.alert.get("body", ""))
        if not _verity_is_blank(body):
            details += "\n\n" + body
        purported_victims_details = self.alert.get("victims")
        if not _verity_is_blank(purported_victims_details):
            details += "\n\n" + "Purported Victims:"
            details += "\n" + json.dumps(purported_victims_details, indent=2, sort_keys=False, default=str)
        return details


class UnknownAlertAdapter(BaseAdapter):
    def __init__(self, alert: dict) -> None:
        super().__init__(alert)

    @property
    def incident_name(self) -> str:
        return "UNKNOWN ALERT TYPE:\n" + "UID: " + str(self.alert.get("id", self.alert.get("uid", "")))

    @property
    def incident_details(self) -> str:
        details = "Source Object: UNKNOWN ALERT TYPE"
        a = self.alert
        if isinstance(a, dict):
            if not _verity_is_blank(a):
                details += "\n\n" + json.dumps(a, indent=2, sort_keys=False, default=str)
        elif isinstance(a, list):
            if not _verity_is_blank(a):
                details += "\n\n" + json.dumps(a, indent=2, sort_keys=False, default=str)
        else:
            plain = html.unescape(" ".join(remove_tags(str(a)).strip().split()))
            if not _verity_is_blank(plain):
                details += "\n\n" + plain
        return details


VERITY471_DOCUMENT_TYPES: dict[str, type] = {
    "actor": ActorAdapter,
    "breach_alerts": BreachAlertAdapter,
    "creds_cred": CredentialAdapter,
    "creds_cred_occurrence": CredentialOccurrenceAdapter,
    "creds_cred_set": CredentialSetAdapter,
    "vulnerabilities_cve": CveReportAdapter,
    "malware_event": MalwareEventAdapter,
    "malware_family": EntityAdapter,
    "malware_indicator": MalwareIndicatorAdapter,
    "chats_message": InstantMessageAdapter,
    "forums_post": ForumPostAdapter,
    "forums_private_message": ForumsPrivateMessageAdapter,
    "fintel": FintelReportAdapter,
    "geopol_reports": GeopolReportAdapter,
    "information_reports": InformationReportAdapter,
    "malware_reports": MalwareReportAdapter,
    "spot_reports": SpotReportAdapter,
}


def compose_verity471_url(alert_details, _id, document_type):
    def _cred_set_url():
        cred_set_name = deep_get(alert_details, "data.name", "")
        encoded_name = quote(f"={cred_set_name}")
        verity_ui_url = (
            f"https://verity.intel471.com/search?category=creds_cred_set&timeFilter=ALL_TIME&q=cred_set.name{encoded_name}"
        )
        return verity_ui_url

    def _report_url():
        verity_report_type = alert_details.get("type").replace("report", "").replace("_", "").lower()
        verity_ui_url = f"https://verity.intel471.com/intelligence/{verity_report_type}ReportView/{_id}"
        return verity_ui_url

    def _forum_post_url():
        forum_id = deep_get(alert_details, "forum.id", "")
        subforum_id = deep_get(alert_details, "sub_forum.id", "")
        thread_id = deep_get(alert_details, "thread.id", "")
        return f"https://verity.intel471.com/sources/forum/{forum_id}/sub-forum/{subforum_id}/thread/{thread_id}"

    def _chat_message_url():
        chat_room_id = deep_get(alert_details, "chat_room.id", None)
        if chat_room_id:
            return f"https://verity.intel471.com/sources/messaging-services/thread/{chat_room_id}"
        return ""

    def _credential_url():
        credential_id = alert_details.get("id")
        return f"https://verity.intel471.com/credentials-dashboard/details/{credential_id}"

    def _malware_family_url():
        return f"https://verity.intel471.com/malware/families/{_id}/report"

    def _vulnerability_url():
        cve_status = deep_get(alert_details, "cve.status", "")
        if cve_status:
            return f"https://verity.intel471.com/vulnerabilities/{cve_status}?vulnerabilityId={_id}"
        return ""

    get_url = {
        "actor": None,
        "breach_alerts": _report_url,
        "creds_cred": _credential_url,
        "creds_cred_occurrence": None,
        "creds_cred_set": _cred_set_url,
        "vulnerabilities_cve": _vulnerability_url,
        "malware_event": None,
        "malware_family": _malware_family_url,
        "malware_indicator": None,
        "chats_message": _chat_message_url,
        "forums_post": _forum_post_url,
        "forums_private_message": None,
        "fintel": _report_url,
        "geopol_reports": _report_url,
        "information_reports": _report_url,
        "malware_reports": _report_url,
        "spot_reports": _report_url,
    }.get(document_type)
    if not get_url:
        return ""
    return get_url()


def compose_incident_watcher_details_verity471(alert: dict, client) -> tuple[str, str]:
    watcher_group_description: str = ""
    watcher_group_id: str | None = alert.get("watcher_group_id")
    watcher_description: str = ""
    watcher_id: str = alert.get("watcher_id", "")
    group_details_response = client.search_watcher_group_details_verity471(watcher_group_id).get("watchers_groups")
    if group_details_response:
        watcher_group = group_details_response[0]
        watcher_group_description = watcher_group.get("description", "")
    watcher_details_response = client.search_watcher_details_verity471(watcher_id).get("watchers")
    if watcher_details_response:
        watcher_details = watcher_details_response[0]
        watcher_description = watcher_details.get("description", "")
    return watcher_group_description, watcher_description


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    message: str = ""
    intel471_backend = demisto.params().get("intel471_backend", "TITAN")
    try:
        watcher_group_uids = demisto.params().get("watcher_group_uids", None)

        max_results = arg_to_number(arg=demisto.params().get("max_fetch"), arg_name="max_fetch", required=False)
        if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
            max_results = MAX_INCIDENTS_TO_FETCH

        first_fetch_time = arg_to_datetime(
            arg=demisto.params().get("first_fetch", "7 days"), arg_name="First fetch time", required=True
        )
        first_fetch_timestamp = int(first_fetch_time.timestamp()) * 1000 if first_fetch_time else None
        # Using assert as a type guard (since first_fetch_time is always an int when required=True)
        assert isinstance(first_fetch_timestamp, int)

        last_alert_uid: str = ""
        last_cursor: str = ""
        if intel471_backend == "TITAN":
            alerts_wrapper: dict = client.search_alerts_titan(
                watcher_group_uids=watcher_group_uids,
                max_results=max_results,
                start_time=first_fetch_timestamp,
                last_alert_uid=last_alert_uid,
            )
        else:
            alerts_wrapper = client.search_alerts_verity471(
                watcher_group_uids=watcher_group_uids,
                max_results=max_results,
                start_time=first_fetch_timestamp,
                last_cursor=last_cursor,
            )
        if alerts_wrapper.get("alerts"):
            message = "ok"
        else:
            raise DemistoException("Unable to obtain Watcher Alerts.")

    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


def fetch_incidents_titan(
    client: Client,
    max_results: int,
    last_run: dict[str, int],
    first_fetch_time: int,
    watcher_group_uids: str | None,
    last_alert_uid: str,
) -> tuple[str, dict[str, int | str], list[dict[Any, Any]]]:
    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch: int = last_run.get("last_fetch", 0)
    # Handle first fetch time
    if last_fetch == 0:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time * 1000
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = last_fetch

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: list[dict[str, Any]] = []

    alerts_wrapper: dict = client.search_alerts_titan(
        watcher_group_uids=watcher_group_uids, max_results=max_results, start_time=last_fetch, last_alert_uid=last_alert_uid
    )

    latest_alert_uid: str = ""

    if alerts_wrapper.get("alerts"):
        watcher_groups: list = []
        if alerts_wrapper.get("watcherGroups"):
            watcher_groups = alerts_wrapper.get("watcherGroups", [])

        alerts: list = alerts_wrapper.get("alerts", [])
        for alert in alerts:
            # If no created_time set is as epoch (0). We use time in ms so we must
            # convert it from the Titan API response
            incident_created_time = int(alert.get("foundTime", "0"))

            incident_name: str | None = compose_incident_title(alert)
            titan_url: str = compose_titan_url(alert)
            watcher_group_description, watcher_description = compose_incident_watcher_details(alert, watcher_groups)
            incident_details: str = compose_incident_details(alert, watcher_groups)

            incident = {
                "name": incident_name,
                "details": incident_details,
                "occurred": timestamp_to_datestring(incident_created_time),
                "rawJSON": json.dumps(alert),
                "type": INCIDENT_TYPE,  # Map to a specific XSOAR incident Type
                "severity": convert_to_demisto_severity(alert.get("severity", "Medium")),
                "CustomFields": {
                    "intel471url": titan_url,
                    "watchergroup": watcher_group_description,
                    "watcher": watcher_description,
                },
            }

            incidents.append(incident)

            latest_alert_uid = alert.get("uid", "")

            # Update last run and add incident if the incident is newer than last fetch
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run: dict[str, int | str] = {"last_fetch": latest_created_time}

    return latest_alert_uid, next_run, incidents


def fetch_incidents_verity471(
    client: Client, max_results: int, last_run: dict[str, int | str], first_fetch_time: int, watcher_group_uids: str | None
) -> tuple[str, dict[str, int | str], list[dict[str, Any]]]:
    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch: int | str = last_run.get("last_fetch", 0)
    last_cursor: str = str(last_run.get("last_cursor", ""))
    # Handle first fetch time
    if last_fetch == 0:
        # if missing, use what provided via first_fetch_time
        latest_created_time = first_fetch_time * 1000
    else:
        # otherwise use the stored last fetch
        latest_created_time = int(last_fetch)
    latest_created_time += 1
    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: list[dict[str, Any]] = []

    alerts_wrapper: dict = client.search_alerts_verity471(
        watcher_group_uids=watcher_group_uids, max_results=max_results, start_time=latest_created_time, last_cursor=last_cursor
    )

    alert_highlight_size = 300
    alerts: list = alerts_wrapper.get("alerts", [])
    for alert in alerts:
        # If no created_time set is as epoch (0). We use time in ms so we must
        # convert it from the Titan API response

        highlights = []
        """[h['field_name']+ " - " + ", ".join(h['snippets']) for h in alert['highlights']]"""
        for h in alert["highlights"]:
            field_name = h["field_name"]
            snippets = []
            for snippet in h["snippets"]:
                snippet_text = remove_tags(snippet)
                if len(snippet_text) > alert_highlight_size:
                    snippet_text = snippet_text[:alert_highlight_size] + "[...]"
                snippets.append(snippet_text)
            snippents = ", ".join(snippets)

            highlights.append(f"{field_name} - {snippents}")
        highlights_str = "\n".join(highlights)

        incident_created_time = as_timestamp(alert.get("creation_ts", "0"))
        alert_details: dict = client.search_alert_details_verity471(deep_get(alert, "links.verity_api.href", {}))
        if not alert_details:
            continue

        adapter_cls = VERITY471_DOCUMENT_TYPES.get(alert.get("source_type", ""), UnknownAlertAdapter)
        adapted_alert = adapter_cls(alert_details)
        incident_name: str = adapted_alert.incident_name
        alert_id = adapted_alert.alert_id
        alert_document_type = alert.get("source_type", "")
        verity471_url: str = compose_verity471_url(alert_details, alert_id, alert_document_type)
        watcher_group_description, watcher_description = compose_incident_watcher_details_verity471(alert, client)
        incident_details: str = adapted_alert.incident_details

        incident = {
            "name": incident_name,
            "details": incident_details,
            "occurred": timestamp_to_datestring(incident_created_time),
            "rawJSON": json.dumps(alert),
            "type": INCIDENT_TYPE,  # Map to a specific XSOAR incident Type
            "severity": convert_to_demisto_severity(alert.get("severity", "Medium")),
            "CustomFields": {
                "intel471url": verity471_url,
                "watchergroup": watcher_group_description,
                "watcher": watcher_description,
                "highlights": highlights_str,
            },
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time
    last_cursor: str = alerts_wrapper.get("cursor_next", "")
    # Save the next_run as a dict with the last_fetch key to be stored
    next_run: dict[str, int | str] = {
        "last_fetch": latest_created_time,
        "last_cursor": last_cursor,
    }

    return last_cursor, next_run, incidents


""" MAIN FUNCTION """


def main() -> None:
    intel471_backend: str = demisto.params().get("intel471_backend", "TITAN")

    if intel471_backend == "TITAN":
        base_url = FEED_URL
    else:
        base_url = FEED_URL_VERITY471
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get("first_fetch", "7 days"), arg_name="First fetch time", required=True
    )
    first_fetch_timestamp: int = int(first_fetch_time.timestamp()) if first_fetch_time else 0
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        headers: dict = {"user-agent": USER_AGENT}

        username = demisto.params().get("credentials", {}).get("identifier")
        password = demisto.params().get("credentials", {}).get("password")

        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, auth=(username, password), proxy=proxy)

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            watcher_group_uids = demisto.params().get("watcher_group_uids", None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(arg=demisto.params().get("max_fetch"), arg_name="max_fetch", required=False)
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            last_alert_uid: str = demisto.getIntegrationContext().get("last_alert_uid", "")

            if intel471_backend == "Verity471":
                latest_alert_uid, next_run, incidents = fetch_incidents_verity471(
                    client=client,
                    max_results=max_results,
                    last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                    first_fetch_time=first_fetch_timestamp,
                    watcher_group_uids=watcher_group_uids,
                )
            else:
                latest_alert_uid, next_run, incidents = fetch_incidents_titan(
                    client=client,
                    max_results=max_results,
                    last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                    first_fetch_time=first_fetch_timestamp,
                    watcher_group_uids=watcher_group_uids,
                    last_alert_uid=last_alert_uid,
                )

            # update the integration context
            if latest_alert_uid:
                demisto.setIntegrationContext({"last_alert_uid": latest_alert_uid})

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
