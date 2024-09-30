import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


"""Recorded Future Integration for Demisto."""

import copy
import platform
from typing import *

# flake8: noqa: F402,F405 lgtm

STATUS_TO_RETRY = [500, 501, 502, 503, 504]

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore

__version__ = "2.5.2"


# === === === === === === === === === === === === === === ===
# === === === === === === HELPERS === === === === === === ===
# === === === === === === === === === === === === === === ===


def translate_score(score: int, threshold: int) -> int:
    """Translate Recorded Future score to DBot score."""
    RISK_SCORE_THRESHOLD = 25
    # See https://support.recordedfuture.com/hc/en-us/articles/115000894468-Vulnerability-Risk-Rules.  # noqa
    if score >= threshold:
        return Common.DBotScore.BAD
    elif score >= RISK_SCORE_THRESHOLD:
        return Common.DBotScore.SUSPICIOUS
    else:
        return Common.DBotScore.NONE


def determine_hash(hash_value: str) -> str:
    """Determine hash type by length."""
    hash_length = len(hash_value)
    if hash_length == 128:
        return "SHA512"
    elif hash_length == 64:
        return "SHA256"
    elif hash_length == 40:
        return "SHA1"
    elif hash_length == 32:
        return "MD5"
    elif hash_length == 8:
        return "CRC32"
    else:
        return "CTPH"


def create_indicator(
    entity: str,
    entity_type: str,
    score: int,
    description: str = "",
    location: Dict[str, Any] = None,
) -> Common.Indicator:
    """Create an Indicator object."""
    demisto_params = demisto.params()

    if location is None:
        location = {}

    thresholds = {
        "file": int(demisto_params.get("file_threshold", 65)),
        "ip": int(demisto_params.get("ip_threshold", 65)),
        "domain": int(demisto_params.get("domain_threshold", 65)),
        "url": int(demisto_params.get("url_threshold", 65)),
        "cve": int(demisto_params.get("cve_threshold", 65)),
    }
    dbot_score = translate_score(score, thresholds[entity_type])
    dbot_description = (
        f"Score above {thresholds[entity_type]}"
        if dbot_score == Common.DBotScore.BAD
        else ""
    )
    dbot_vendor = "Recorded Future v2"
    if entity_type == "ip":
        return Common.IP(
            entity,
            Common.DBotScore(
                entity,
                DBotScoreType.IP,
                dbot_vendor,
                dbot_score,
                dbot_description,
                reliability=demisto.params().get("integrationReliability"),
            ),
            asn=location.get("asn", None),
            geo_country=location.get("location", {}).get("country", None),
        )
    elif entity_type == "domain":
        return Common.Domain(
            entity,
            Common.DBotScore(
                entity,
                DBotScoreType.DOMAIN,
                dbot_vendor,
                dbot_score,
                dbot_description,
                reliability=demisto.params().get("integrationReliability"),
            ),
        )
    elif entity_type == "file":
        dbot_obj = Common.DBotScore(
            entity,
            DBotScoreType.FILE,
            dbot_vendor,
            dbot_score,
            dbot_description,
            reliability=demisto.params().get("integrationReliability"),
        )
        hash_type = determine_hash(entity)
        if hash_type == "MD5":
            return Common.File(dbot_obj, md5=entity)
        elif hash_type == "SHA1":
            return Common.File(dbot_obj, sha1=entity)
        elif hash_type == "SHA256":
            return Common.File(dbot_obj, sha256=entity)
        elif hash_type == "SHA512":
            return Common.File(dbot_obj, sha512=entity)
        else:
            return Common.File(dbot_obj)
    elif entity_type == "cve":
        return Common.CVE(entity, "", "", "", description)
    elif entity_type == "url":
        return Common.URL(
            entity,
            Common.DBotScore(
                entity,
                DBotScoreType.URL,
                dbot_vendor,
                dbot_score,
                dbot_description,
                reliability=demisto.params().get("integrationReliability"),
            ),
        )
    else:
        raise Exception(
            f"Could not create indicator for this type of entity: {entity_type}"
        )


# === === === === === === === === === === === === === === ===
# === === === === Recorded Future API Client === === === ====
# === === === === === === === === === === === === === === ===


class Client(BaseClient):
    def whoami(self) -> Dict[str, Any]:

        return self._http_request(
            method="get",
            url_suffix="info/whoami",
            timeout=60,
        )

    def _key_extraction(self, data, keys_to_keep):
        return {key: data[key] for key in set(data.keys()) & keys_to_keep}

    def _clean_calling_context(self, calling_context):
        calling_context_keys_to_keep = {"args", "command", "params", "context"}
        context_keys_to_keep = {"Incidents", "IntegrationInstance", "ParentEntry"}
        incidents_keys_to_keep = {"name", "type", "id"}
        parent_entry_keys_to_keep = {"entryTask", "scheduled", "recurrent"}

        if context := calling_context.get("context", None):
            context = self._key_extraction(context, context_keys_to_keep)

            if incidents := context.get("Incidents", {}):
                incidents = [
                    self._key_extraction(incident, incidents_keys_to_keep)
                    for incident in incidents
                ]
                context["Incidents"] = incidents

            if parent_entry := context.get("ParentEntry", {}):
                parent_entry = self._key_extraction(
                    parent_entry, parent_entry_keys_to_keep
                )
                context["ParentEntry"] = parent_entry
            calling_context["context"] = context

        calling_context = self._key_extraction(
            calling_context, calling_context_keys_to_keep
        )
        return calling_context

    def _get_writeback_data(self):

        if (
            demisto.params().get("collective_insights") == "On"
            and demisto.args().get("collective_insights") != "off"
        ) or demisto.args().get("collective_insights") == "on":
            do_track = True
        else:
            do_track = False

        if do_track and demisto.callingContext:
            calling_context = copy.deepcopy(demisto.callingContext)
            calling_context.get("context", {}).pop("ExecutionContext", None)
            calling_context = self._clean_calling_context(calling_context)
            return calling_context

        return None

    def _call(self, url_suffix, **kwargs):

        json_data = {
            "demisto_command": demisto.command(),
            "demisto_args": demisto.args(),
        }

        request_kwargs = {
            "method": "post",
            "url_suffix": url_suffix,
            "json_data": json_data,
            "timeout": 90,
            "retries": 3,
            "status_list_to_retry": STATUS_TO_RETRY,
        }

        request_kwargs.update(kwargs)

        # This need to be after 'request_kwargs.update(kwargs)'.
        calling_context = self._get_writeback_data()
        if calling_context:
            request_kwargs["json_data"]["callingContext"] = calling_context

        try:
            response = self._http_request(**request_kwargs)

            if isinstance(response, dict) and response.get("return_error"):
                # This will raise the Exception or call "demisto.results()" for the error and sys.exit(0).
                return_error(**response["return_error"])

        except DemistoException as err:
            if "404" in str(err):
                return CommandResults(
                    outputs_prefix="",
                    outputs={},
                    raw_response={},
                    readable_output="No results found.",
                    outputs_key_field="",
                )
            else:
                raise err

        return response

    def fetch_incidents(self) -> Dict[str, Any]:
        """Fetch incidents."""
        return self._call(
            url_suffix="/v2/alert/fetch_incidents",
            json_data={
                "demisto_command": demisto.command(),
                "demisto_args": demisto.args(),
                "demisto_params": demisto.params(),
                "demisto_last_run": demisto.getLastRun(),
            },
            timeout=120,
        )

    def entity_search(self) -> Dict[str, Any]:
        """Search for entities with entity type."""
        return self._call(url_suffix="/v2/search")

    def entity_lookup(self) -> Dict[str, Any]:
        """Entity lookup."""
        return self._call(url_suffix="/v2/lookup/reputation", timeout=120)

    def get_intelligence(self) -> Dict[str, Any]:
        """Entity enrich."""
        return self._call(url_suffix="/v2/lookup/intelligence")

    def get_links(self) -> Dict[str, Any]:
        """Entity enrich."""
        return self._call(url_suffix="/v2/lookup/links")

    def get_single_alert(self) -> dict:
        """Get a single alert"""
        return self._call(url_suffix="/v2/alert/lookup")

    def get_alerts(self) -> Dict[str, Any]:
        """Get alerts."""
        return self._call(url_suffix="/v2/alert/search")

    def get_alert_rules(self) -> Dict[str, Any]:
        """Get alert rules."""
        return self._call(url_suffix="/v2/alert/rule")

    def alert_set_status(self, data=None):
        """Update alert."""
        # If data is None - we have alert_id and status in demisto.args().
        return self._call(
            url_suffix="/v2/alert/set_status",
            json_data={
                "demisto_command": demisto.command(),
                "demisto_args": demisto.args(),
                "alerts_update_data": data,
            },
        )

    def alert_set_note(self, data=None):
        """Update alert."""
        # If data is None - we have alert_id and note in demisto.args().
        return self._call(
            url_suffix="/v2/alert/set_note",
            json_data={
                "demisto_command": demisto.command(),
                "demisto_args": demisto.args(),
                "alerts_update_data": data,
            },
        )

    def get_triage(self) -> Dict[str, Any]:
        """SOAR triage lookup."""
        return self._call(url_suffix="/v2/lookup/triage")

    def get_threat_map(self) -> Dict[str, Any]:
        return self._call(url_suffix="/v2/threat/actors")

    def get_threat_links(self) -> Dict[str, Any]:
        return self._call(url_suffix="/v2/links/search")

    def get_detection_rules(self) -> Dict[str, Any]:
        return self._call(url_suffix="/v2/detection_rules/search")

    def submit_detection_to_collective_insight(self) -> Dict[str, Any]:
        return self._call(url_suffix="/v2/collective-insights/detections")


# === === === === === === === === === === === === === === ===
# === === === === === === ACTIONS === === === === === === ===
# === === === === === === === === === === === === === === ===


class Actions:
    def __init__(self, rf_client: Client):
        self.client = rf_client

    def _process_result_actions(
        self, response: Union[dict, CommandResults]
    ) -> List[CommandResults]:

        if isinstance(response, CommandResults):
            # Case when we got 404 on response, and it was processed in self.client._call() method.
            return [response]
        elif not isinstance(response, dict):
            # In case API returned a str - we don't want to call "response.get()" on a str object.
            return None  # type: ignore

        result_actions: Union[List[dict], None] = response.get("result_actions")

        if not result_actions:
            return None  # type: ignore

        command_results: List[CommandResults] = list()
        for action in result_actions:
            if "create_indicator" in action:
                indicator = create_indicator(**action["create_indicator"])
                if "CommandResults" in action:
                    # Custom CommandResults.
                    command_results_kwargs = action["CommandResults"]
                    command_results_kwargs["indicator"] = indicator
                    command_results.append(CommandResults(**command_results_kwargs))
                else:
                    # Default CommandResults after indicator creation.
                    command_results.append(
                        CommandResults(
                            readable_output=tableToMarkdown(
                                "New indicator was created.", indicator.to_context()
                            ),
                            indicator=indicator,
                        )
                    )
            elif "CommandResults" in action:
                command_results.append(CommandResults(**action["CommandResults"]))

        return command_results

    def fetch_incidents(self) -> None:

        response = self.client.fetch_incidents()

        if isinstance(response, CommandResults):
            # 404 case.
            return

        if (
                response.get("incidents") is not None
                and response.get("demisto_last_run")
        ):
            incidents = response["incidents"]
            demisto_last_run = response["demisto_last_run"]

            demisto.incidents(incidents)
            demisto.setLastRun(demisto_last_run)

            update_alert_status = response.pop("alerts_update_data", None)
            if update_alert_status:
                self.client.alert_set_status(update_alert_status)

    def malware_search_command(self) -> List[CommandResults]:
        """Malware search command."""
        response = self.client.entity_search()
        return self._process_result_actions(response=response)

    def lookup_command(self) -> List[CommandResults]:
        """Entity lookup command."""
        response = self.client.entity_lookup()
        return self._process_result_actions(response=response)

    def intelligence_command(self) -> List[CommandResults]:
        """Enrich command."""
        response = self.client.get_intelligence()
        return self._process_result_actions(response=response)

    def get_links_command(self) -> List[CommandResults]:
        response = self.client.get_links()
        return self._process_result_actions(response=response)

    def get_single_alert_command(self) -> Union[List[CommandResults], dict]:
        """Command to get a single alert."""
        response = self.client.get_single_alert()
        result_actions = self._process_result_actions(response=response)
        if result_actions:
            # If no actual data is present, we will have CommandResults with corresponding message.
            return result_actions
        else:
            return response

    def get_alerts_command(self) -> Dict[str, Any]:
        """Get Alerts Command."""
        response = self.client.get_alerts()
        return response

    def get_alert_rules_command(self) -> Dict[str, Any]:
        """Get Alert Rules Command."""
        response = self.client.get_alert_rules()
        return response

    def alert_set_status_command(self):
        response = self.client.alert_set_status()
        return self._process_result_actions(response=response)

    def alert_set_note_command(self):
        response = self.client.alert_set_note()
        return self._process_result_actions(response=response)

    def triage_command(self) -> List[CommandResults]:
        """Do Auto Triage."""
        response = self.client.get_triage()
        return self._process_result_actions(response=response)

    def threat_actors_command(self) -> List[CommandResults]:
        response = self.client.get_threat_map()
        return self._process_result_actions(response=response)

    def threat_links_command(self) -> List[CommandResults]:
        response = self.client.get_threat_links()
        return self._process_result_actions(response=response)

    def detection_rules_command(self) -> List[CommandResults]:
        response = self.client.get_detection_rules()
        return self._process_result_actions(response=response)

    def collective_insight_command(self) -> List[CommandResults]:
        response = self.client.submit_detection_to_collective_insight()
        return self._process_result_actions(response=response)


# === === === === === === === === === === === === === === ===
# === === === === === === === MAIN === === === === === === ==
# === === === === === === === === === === === === === === ===


def main() -> None:  # pragma: no cover
    """Main method used to run actions."""
    try:
        demisto_params = demisto.params()
        base_url = demisto_params.get("server_url", "").rstrip("/")
        verify_ssl = not demisto_params.get("insecure", False)
        proxy = demisto_params.get("proxy", False)
        api_token = demisto_params.get("token_credential", {}).get(
            "password"
        ) or demisto_params.get("token")
        if not api_token:
            return_error("Please provide a valid API token")
        headers = {
            "X-RFToken": api_token,
            "X-RF-User-Agent": (
                f"RecordedFuture.py/{__version__} ({platform.platform()}) "
                f"XSOAR/{__version__} "
                f'RFClient/{__version__} (Cortex_XSOAR_{demisto.demistoVersion()["version"]})'
            ),
        }
        client = Client(
            base_url=base_url, verify=verify_ssl, headers=headers, proxy=proxy
        )
        command = demisto.command()
        actions = Actions(client)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            # Returning 'ok' indicates that the integration works like it suppose to and
            # connection to the service is successful.
            # Returning 'ok' will make the test result be green.
            # Any other response will make the test result be red.

            try:
                client.whoami()
                return_results("ok")
            except Exception as err:
                message = str(err)
                try:
                    error = json.loads(str(err).split("\n")[1])
                    if "fail" in error.get("result", {}).get("status", ""):
                        message = error.get("result", {})["message"]
                except Exception:
                    message = (
                        "Unknown error. Please verify that the API"
                        f" URL and Token are correctly configured. RAW Error: {err}"
                    )
                raise DemistoException(f"Failed due to - {message}")

        elif command == "fetch-incidents":
            actions.fetch_incidents()

        elif command == "recordedfuture-malware-search":
            return_results(actions.malware_search_command())

        elif command in ["url", "ip", "domain", "file", "cve"]:
            return_results(actions.lookup_command())

        elif command == "recordedfuture-intelligence":
            return_results(actions.intelligence_command())

        elif command == "recordedfuture-links":
            return_results(actions.get_links_command())

        elif command == "recordedfuture-single-alert":
            return_results(actions.get_single_alert_command())

        elif command == "recordedfuture-alerts":
            return_results(actions.get_alerts_command())

        elif command == "recordedfuture-alert-rules":
            return_results(actions.get_alert_rules_command())

        elif command == "recordedfuture-alert-set-status":
            return_results(actions.alert_set_status_command())

        elif command == "recordedfuture-alert-set-note":
            return_results(actions.alert_set_note_command())

        elif command == "recordedfuture-threat-assessment":
            return_results(actions.triage_command())

        elif command == "recordedfuture-threat-map":
            return_results(actions.threat_actors_command())
        elif command == "recordedfuture-threat-links":
            return_results(actions.threat_links_command())
        elif command == "recordedfuture-detection-rules":
            return_results(actions.detection_rules_command())
        elif command == "recordedfuture-collective-insight":
            return_results(actions.collective_insight_command())

    except Exception as e:
        return_error(
            message=f"Failed to execute {demisto.command()} command: {str(e)}",
            error=e,
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
