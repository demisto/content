"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import concurrent.futures
import platform
from typing import Any

import urllib3
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

MAX_IMAGES_TO_FETCH = 25

STATUS_TO_RETRY = [500, 501, 502, 503, 504]

__version__ = "0.1.0"

TIMEOUT_60 = 60
TIMEOUT_90 = 90
TIMEOUT_120 = 120

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def _call(self, **kwargs: Any) -> dict | list[CommandResults]:
        try:
            response: dict = self._http_request(**kwargs)
            if not isinstance(response, dict):
                return_error(f"Bad Response, response was not a dict: {str(response)}")

            if response.get("return_error"):
                # This will raise the Exception or call "demisto.results()" for the error and sys.exit(0).
                return_error(**response["return_error"])

            result_actions = response.get("result_actions")
            if isinstance(result_actions, list):
                return [
                    # Take all CommandResults params verbatim from the response, except the `outputs` param,
                    # which is taken from `raw_response.outputs` to minimize payload size
                    CommandResults(outputs=result_action.get("raw_response", {}).get("outputs", None), **result_action)
                    for result_action in result_actions
                    if isinstance(result_action, dict)
                ]
            elif result_actions:
                return_error(f"Bad Response, result_actions was present but not a list: {str(response)}")
            else:
                # We called an endpoint that didn't try to return command results (e.g. fetch-incidents),
                # should just pass response object directly to XSOAR
                return response

        except DemistoException as err:
            if "404" in str(err):
                return [
                    CommandResults(
                        outputs_prefix="",
                        outputs={},
                        raw_response={},
                        readable_output="No results found.",
                        outputs_key_field="",
                    )
                ]
            raise err

    def _get(
        self,
        url_suffix: str,
        *,
        params: dict | None = None,
        timeout: int = 90,
        retries: int = 3,
    ) -> dict | list[CommandResults]:
        return self._call(
            method="GET",
            url_suffix=url_suffix,
            params=params,
            timeout=timeout,
            retries=retries,
            status_list_to_retry=STATUS_TO_RETRY,
        )

    def _post(
        self,
        url_suffix: str,
        json_data: dict,
        timeout: int = 90,
        retries: int = 3,
    ) -> dict | list[CommandResults]:
        return self._call(
            method="POST",
            url_suffix=url_suffix,
            json_data=json_data,
            timeout=timeout,
            retries=retries,
            status_list_to_retry=STATUS_TO_RETRY,
        )

    def whoami(self) -> dict:
        return self._get(
            url_suffix="/info/whoami",
            timeout=60,
        )

    def alert_update(self) -> dict | list[CommandResults]:
        """Update alert"""
        return self._post(
            url_suffix="/v3/alert/update",
            json_data=demisto.args(),
            timeout=90,
        )

    def alert_search(self) -> dict | list[CommandResults]:
        """Search alerts"""
        return self._get(url_suffix="/v3/alert/search", params=demisto.args())

    def alert_rule_search(self) -> dict | list[CommandResults]:
        """Search alert rules."""
        return self._get(url_suffix="/v3/alert/rules", params=demisto.args())

    def alert_lookup(self, alert_id: str) -> dict:
        return self._get(
            url_suffix="/v3/alert/lookup",
            params={"alert_id": alert_id},
            timeout=90,
        )

    def get_alert_image(
        self,
        alert_type: str,
        alert_id: str,
        image_id: str,
        alert_subtype: str | None,
    ) -> bytes:
        """
        Get an image from the v3 alert image endpoint.
        Returns the raw binary content of the image.
        """
        response_content: Any = self._http_request(
            method="get",
            url_suffix="/v3/alert/image",
            params={
                "alert_type": alert_type,
                "alert_subtype": alert_subtype,
                "alert_id": alert_id,
                "image_id": image_id,
            },
            timeout=90,
            resp_type="content",
        )
        return response_content

    def fetch_incidents(self) -> dict:
        """Fetch incidents."""
        classic_query_params = demisto.getLastRun().get("next_query_classic", {})
        playbook_query_params = demisto.getLastRun().get("next_query_playbook", {})
        return self._post(
            url_suffix="/v3/alert/fetch",
            json_data={
                "integration_config": demisto.params(),
                "classic_query_params": classic_query_params,
                "playbook_query_params": playbook_query_params,
            },
            timeout=120,
        )


# === === === === === === === === === === === === === === ===
# === === === === === === ACTIONS === === === === === === ===
# === === === === === === === === === === === === === === ===


class Actions:
    def __init__(self, rf_client: Client):
        self.client = rf_client

    def test_module(self) -> None:
        # This is the call made when pressing the integration Test button.
        # Returning 'ok' indicates that the integration works like it suppose to and
        # connection to the service is successful.
        # Returning 'ok' will make the test result be green.
        # Any other response will make the test result be red.

        demisto_params = demisto.params()

        # Validate first_fetch
        first_fetch = str(demisto_params.get("first_fetch", ""))

        if first_fetch.isnumeric():
            first_fetch = int(first_fetch)
        else:
            raise ValueError("'first_fetch' parameter must be a number")
        ninety_days_in_minutes = 90 * 24 * 60
        if first_fetch > ninety_days_in_minutes:
            raise ValueError("'first_fetch' parameter cannot be bigger than 90 days")

        # Validate max_fetch
        max_fetch = str(demisto_params.get("max_fetch", ""))
        if max_fetch.isnumeric():
            max_fetch = int(max_fetch)
        else:
            raise ValueError("'max_fetch' parameter must be a number")
        if max_fetch > 50:
            raise ValueError("'max_fetch' parameter cannot be bigger than 50")

        try:
            self.client.whoami()
            return_results("ok")
        except Exception as err:
            message = str(err)
            try:
                error = json.loads(str(err).split("\n")[1])
                if "fail" in error.get("result", {}).get("status", ""):
                    message = error.get("result", {})["message"]
            except Exception:
                message = f"Unknown error. Please verify that the API URL and Token are correctly configured. RAW Error: {err}"
            raise DemistoException(f"Failed due to - {message}")

    def fetch_incidents(self) -> None:
        response = self.client.fetch_incidents()
        if isinstance(response, CommandResults):
            # 404.
            return_error("404 in fetch incidents")
            return []
        alerts = response.get("alerts", [])
        next_query_classic = response.get("next_query_classic", {})
        next_query_playbook = response.get("next_query_playbook", {})
        next_query = {
            "next_query_classic": next_query_classic,
            "next_query_playbook": next_query_playbook,
        }

        incidents = [
            {
                "name": alert.get("title"),
                "occurred": alert.get("created"),
                "dbotMirrorId": alert.get("id"),
                "rawJSON": json.dumps(alert),
            }
            for alert in alerts
        ]

        demisto.incidents(incidents)
        demisto.setLastRun(next_query)
        return None

    def alert_search_command(self) -> dict | list[CommandResults]:
        return self.client.alert_search()

    def alert_rule_search_command(
        self,
    ) -> dict | list[CommandResults]:
        return self.client.alert_rule_search()

    def alert_update_command(self) -> dict | list[CommandResults]:
        return self.client.alert_update()

    @staticmethod
    def _get_file_name_from_image_id(image_id: str) -> str:
        return f"{image_id.replace('img:', '')}.png"

    def _get_image_and_create_attachment(
        self,
        alert_type: str,
        alert_id: str,
        image_id: str,
        alert_subtype: str | None,
    ) -> dict | None:
        try:
            return_results(f"Trying to fetch {image_id=} ({alert_type=} {alert_subtype=} {alert_id=})")
            image_content = self.client.get_alert_image(
                alert_type=alert_type,
                alert_id=alert_id,
                image_id=image_id,
                alert_subtype=alert_subtype,
            )
            return_results(f"Fetched {image_id=} ({alert_type=} {alert_subtype=} {alert_id=}): {image_content[:50]} (truncated)")
            file_name = self._get_file_name_from_image_id(image_id)
            file_result_obj = fileResult(file_name, image_content)
            demisto.results(file_result_obj)  # Important
            attachment = {
                "description": "Alert image",
                "name": file_result_obj.get("File"),
                "path": file_result_obj.get("FileID"),
                "showMediaFile": True,
            }
            return attachment
        except Exception as e:
            demisto.error(f"Failed to fetch image {image_id}: {str(e)}")
            return None

    def get_alert_images_command(self) -> list[CommandResults]:
        incident = demisto.incident()
        alert_id = incident.get("CustomFields", {}).get("alertid")
        if not alert_id:
            return_error("Failed to get alert id from incident.")

        lookup_result = self.client.alert_lookup(alert_id)

        if isinstance(lookup_result, list) and lookup_result and isinstance(lookup_result[0], CommandResults):
            lookup_data = lookup_result[0].outputs
        else:
            return_error("Failed to lookup alert.")
            return  # noqa

        alert_type = lookup_data.get("type")
        alert_subtype = lookup_data.get("subtype")

        image_ids = lookup_data.get("images", []) or []

        if not image_ids:
            return [CommandResults(readable_output="No screenshots found in alert details.")]

        context = demisto.context()

        files = demisto.get(context, "File")
        if not files:
            files = []
        if not isinstance(files, list):
            files = [files]

        existing_file_names = {f.get("Name") for f in files}

        # Determine missing image IDs.
        missing_image_ids = set()
        for img_id in image_ids:
            # Limit to only 25 images.
            if len(missing_image_ids) >= MAX_IMAGES_TO_FETCH:
                break

            file_name = self._get_file_name_from_image_id(img_id)
            if file_name not in existing_file_names:
                missing_image_ids.add(img_id)

        if not missing_image_ids:
            return [CommandResults(readable_output="No new images to fetch.")]

        # Fetch missing images concurrently using thread pool.
        new_attachments = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}

            for img_id in missing_image_ids:
                future = executor.submit(
                    self._get_image_and_create_attachment,
                    alert_type=alert_type,
                    alert_id=alert_id,
                    image_id=img_id,
                    alert_subtype=alert_subtype,
                )
                futures[future] = img_id

            for future in concurrent.futures.as_completed(futures):
                attachment = future.result()
                if attachment:
                    new_attachments.append(attachment)

        if not new_attachments:
            return [
                CommandResults(
                    readable_output="No new images were fetched.",
                )
            ]

        message = f"Fetched {len(new_attachments)} new image(s)."
        return [
            CommandResults(
                readable_output=message,
            )
        ]


def get_client():
    demisto_params = demisto.params()

    base_url = demisto_params.get("url", "").rstrip("/")
    verify_ssl = not demisto_params.get("insecure", False)
    proxy = demisto_params.get("proxy", False)

    api_token = demisto_params.get("apikey")
    if not api_token:
        return_error("Please provide a valid API token")

    headers = {
        "X-RFToken": api_token,
        "X-RF-User-Agent": (
            f"RecordedFuture.py/{__version__} ({platform.platform()}) "
            f"XSOAR/{__version__} "
            f"RFClient/{__version__} (Cortex_XSOAR_{demisto.demistoVersion()['version']})"
        ),
    }
    return Client(base_url=base_url, verify=verify_ssl, headers=headers, proxy=proxy)


def main():
    try:
        client = get_client()

        command = demisto.command()
        actions = Actions(client)

        if command == "test-module":
            actions.test_module()
        elif command == "fetch-incidents":
            actions.fetch_incidents()
        elif command == "rf-alert-rules":
            return_results(actions.alert_rule_search_command())
        elif command == "rf-alerts":
            return_results(actions.alert_search_command())
        elif command == "rf-alert-update":
            return_results(actions.alert_update_command())
        elif command == "rf-alert-images":
            return_results(actions.get_alert_images_command())

    except Exception as e:
        return_error(
            message=f"Failed to execute {demisto.command()} command: {str(e)}",
            error=e,
        )


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
