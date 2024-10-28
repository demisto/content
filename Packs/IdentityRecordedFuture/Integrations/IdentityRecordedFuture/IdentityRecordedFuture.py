import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Recorded Future Identity Integration for XSOAR."""
import base64
import json
import platform
from typing import Any, Dict, List, Optional

import requests

# flake8: noqa: F402,F405 lgtm

STATUS_TO_RETRY = [500, 501, 502, 503, 504]

# disable insecure warnings
# pylint:disable=no-member
requests.packages.urllib3.disable_warnings()  # type: ignore

__version__ = "2.0.4"

TIMEOUT_60 = 60
TIMEOUT_90 = 90
TIMEOUT_120 = 120


class Client(BaseClient):
    def whoami(self) -> Dict[str, Any]:
        """Entity lookup."""
        return self._http_request(
            method="get",
            url_suffix="info/whoami",
            timeout=TIMEOUT_60,
        )

    def _call(self, url_suffix: str, **kwargs):

        json_data = {
            "demisto_command": demisto.command(),
            "demisto_args": demisto.args(),
            "demisto_params": demisto.params(),
            "demisto_last_run": demisto.getLastRun(),
        }

        overwrite_keys = (
            "demisto_command",
            "demisto_args",
            "demisto_params",
            "demisto_last_run",
        )
        for k in overwrite_keys:
            if k in kwargs:
                v = kwargs.pop(k)
                json_data[k] = v

        method = kwargs.get("method", "post")

        request_kwargs = {
            "method": method,
            "url_suffix": url_suffix,
            "json_data": json_data,
            "timeout": TIMEOUT_90,
            "retries": 3,
            "status_list_to_retry": STATUS_TO_RETRY,
        }

        request_kwargs.update(kwargs)

        try:
            response = self._http_request(**request_kwargs)

            if isinstance(response, dict) and response.get("return_error"):
                # This will raise the Exception or call "demisto.results()" for the error and sys.exit(0).
                return_error(**response["return_error"])

            return response

        except DemistoException as err:
            if "404" in str(err):
                return CommandResults(
                    outputs_prefix="",
                    outputs={},
                    raw_response={},
                    readable_output="No results found.",
                    outputs_key_field="",
                )
            elif err.res is not None:
                try:
                    error_response_json = err.res.json()
                    # This will raise the Exception or call "demisto.results()" for the error and sys.exit(0).
                    return_error(message=error_response_json["message"])
                except (json.JSONDecodeError, KeyError):
                    raise err
            else:
                raise err

    #######################################################
    ################## Identity API ####################
    #######################################################

    def credentials_search(self) -> Dict[str, Any]:
        """Identity search."""
        return self._call(url_suffix="/v2/identity/credentials/search")

    def credentials_lookup(self) -> Dict[str, Any]:
        """Identity Lookup."""
        return self._call(url_suffix="/v2/identity/credentials/lookup")

    def password_lookup(self) -> Dict[str, Any]:
        """Password Lookup."""
        return self._call(url_suffix="/v2/identity/password/lookup")

    #######################################################
    ################## Playbook alerts ####################
    #######################################################

    def fetch_incidents(self) -> Dict[str, Any]:
        """Fetch incidents."""
        return self._call(
            url_suffix="/playbook_alert/fetch",
            timeout=TIMEOUT_120,
        )

    def search_playbook_alerts(self) -> Dict[str, Any]:
        return self._call(url_suffix="/playbook_alert/search")

    def details_playbook_alerts(self) -> Dict[str, Any]:
        """Get details of a playbook alert"""
        return self._call(url_suffix="/playbook_alert/lookup")

    def update_playbook_alerts(self) -> Dict[str, Any]:
        return self._call(url_suffix="/playbook_alert/update")


#######################################################
###################### Actions ########################
#######################################################


class Actions:
    def __init__(self, rf_client: Client):
        self.client = rf_client

    def _process_result_actions(
        self, response: Union[dict, CommandResults]
    ) -> Optional[List[CommandResults]]:

        if isinstance(response, CommandResults):
            # Case when we got 404 on response, and it was processed in self.client._call() method.
            return [response]
        elif not isinstance(response, dict):
            # In case API returned a str - we don't want to call "response.get()" on a str object.
            return None

        action_result: Optional[dict] = response.get("action_result")

        result_actions: Optional[List[dict]] = response.get("result_actions")

        if not any([action_result, result_actions]):
            return None

        if action_result:
            command_results = [CommandResults(**action_result)]
        elif result_actions:
            command_results: List[CommandResults] = []  # type: ignore[no-redef]
            for action in result_actions:
                if "CommandResults" in action:
                    command_results.append(CommandResults(**action["CommandResults"]))
        else:
            # Impossible case.
            return None

        return command_results

    def identity_search_command(self):
        response = self.client.credentials_search()
        return self._process_result_actions(response=response)

    def identity_lookup_command(self):
        """Lookup command for identities"""
        response = self.client.credentials_lookup()
        return self._process_result_actions(response=response)

    def password_lookup_command(self):
        """Lookup command for passwords"""
        response = self.client.password_lookup()
        return self._process_result_actions(response=response)

    #######################################################
    ################## Playbook alerts ####################
    #######################################################

    def fetch_incidents(self) -> None:

        response = self.client.fetch_incidents()

        if isinstance(response, CommandResults):
            # 404 case.
            return

        for _key, _val in response.items():
            if _key == "demisto_last_run":
                demisto.setLastRun(_val)
            if _key == "incidents":
                self._transform_incidents_attachments(_val)
                demisto.incidents(_val)

    def playbook_alert_search_command(self) -> Optional[List[CommandResults]]:
        response = self.client.search_playbook_alerts()
        return self._process_result_actions(response=response)

    def playbook_alert_details_command(self) -> Optional[List[CommandResults]]:
        response = self.client.details_playbook_alerts()
        return self._process_result_actions(response=response)

    def playbook_alert_update_command(self) -> Optional[List[CommandResults]]:
        response = self.client.update_playbook_alerts()
        return self._process_result_actions(response=response)

    @staticmethod
    def _transform_incidents_attachments(incidents: list) -> None:
        for incident in incidents:
            attachments = []
            incident_json = json.loads(incident.get("rawJSON", "{}"))
            if incident_json.get("panel_evidence_summary", {}).get("screenshots"):
                for screenshot_data in incident_json["panel_evidence_summary"][
                    "screenshots"
                ]:
                    file_name = (
                        f"{screenshot_data.get('image_id', '').replace('img:', '')}.png"
                    )
                    file_data = screenshot_data.get("base64", "")
                    file = fileResult(file_name, base64.b64decode(file_data))
                    attachment = {
                        "description": screenshot_data.get("description"),
                        "name": file.get("File"),
                        "path": file.get("FileID"),
                        "showMediaFile": True,
                    }
                    attachments.append(attachment)
                incident["attachment"] = attachments


# === === === === === === === === === === === === === === ===
# === === === === === === === MAIN === === === === === === ==
# === === === === === === === === === === === === === === ===


def get_client(proxies: dict) -> Client:
    demisto_params = demisto.params()
    base_url = demisto_params.get("server_url", "").rstrip("/")
    verify_ssl = not demisto_params.get("unsecure", False)

    api_token = demisto_params.get("credential", {}).get(
        "password"
    ) or demisto_params.get("token")

    if not api_token:
        return_error(message="Please provide a valid API token")

    headers = {
        "X-RFToken": api_token,
        "X-RF-User-Agent": (
            f"xsoar-identity/rfclient/{__version__} ({platform.platform()}) "
            f"(Cortex_XSOAR_{demisto.demistoVersion()['version']})"
        ),
    }

    client = Client(
        base_url=base_url,
        verify=verify_ssl,
        headers=headers,
        proxy=bool(proxies),
    )

    return client


def main() -> None:
    """Main method used to run actions."""
    try:
        proxies = handle_proxy()
        client = get_client(proxies=proxies)
        actions = Actions(client)

        command = demisto.command()

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            # Returning "ok" indicates that the integration works like it suppose to and
            # connection to the service is successful.
            # Returning "ok" will make the test result be green.
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

        elif command == "recordedfuture-password-lookup":
            return_results(actions.password_lookup_command())

        elif command == "recordedfuture-identity-search":
            return_results(actions.identity_search_command())

        elif command == "recordedfuture-identity-lookup":
            return_results(actions.identity_lookup_command())

        #######################################################
        ################## Playbook alerts ####################
        #######################################################

        elif command == "fetch-incidents":
            actions.fetch_incidents()

        elif command == "recordedfuture-identity-playbook-alerts-search":
            return_results(actions.playbook_alert_search_command())

        elif command == "recordedfuture-identity-playbook-alerts-details":
            return_results(actions.playbook_alert_details_command())

        elif command == "recordedfuture-identity-playbook-alerts-update":
            return_results(actions.playbook_alert_update_command())

        else:
            return_error(message=f"Unknown command: {command}")

    except Exception as e:
        return_error(
            message=f"Failed to execute {demisto.command()} command. Error: {str(e)}",
            error=e,
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
