import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Recorded Future Identity Integration for Demisto."""
from typing import Dict, Any, Union, Optional
import requests
import json

# flake8: noqa: F402,F405 lgtm

STATUS_TO_RETRY = [500, 501, 502, 503, 504]


# disable insecure warnings
# pylint:disable=no-member
requests.packages.urllib3.disable_warnings()  # type: ignore

__version__ = "1.0"


class Client(BaseClient):
    def whoami(self) -> Dict[str, Any]:
        """Entity lookup."""
        return self._http_request(
            method="get",
            url_suffix="info/whoami",
            timeout=60,
        )

    def _call(self, url_suffix: str):
        json_data = {
            "demisto_args": demisto.args(),
            "demisto_params": demisto.params(),
        }

        request_kwargs = {
            "method": "post",
            "url_suffix": url_suffix,
            "json_data": json_data,
            "timeout": 90,
            "retries": 3,
            "status_list_to_retry": STATUS_TO_RETRY,
        }

        try:
            response = self._http_request(**request_kwargs)
            return response
        except DemistoException as err:
            if "404" in str(err):
                return CommandResults(
                    outputs_prefix="",
                    outputs=dict(),
                    raw_response=dict(),
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

    def identity_search(self) -> Dict[str, Any]:
        """Identity search."""
        return self._call(url_suffix="/v2/identity/credentials/search")

    def identity_lookup(self) -> Dict[str, Any]:
        """Identity Lookup."""
        return self._call(url_suffix="/v2/identity/credentials/lookup")

    def password_lookup(self) -> Dict[str, Any]:
        """Password Lookup."""
        return self._call(url_suffix="/v2/identity/password/lookup")


#####################
#    Actions        #
#####################


class Actions:
    def __init__(self, rf_client: Client):
        self.client = rf_client

    def _process_result_actions(
        self, response: Union[dict, CommandResults]
    ) -> Optional[CommandResults]:
        if isinstance(response, CommandResults):
            # Case when we got 404 on response, and it was processed in self.client._call() method.
            return response
        elif not isinstance(response, dict):
            # In case API returned a str - we don't want to call "response.get()" on a str object.
            return None

        action_result: Optional[dict] = response.get("action_result")

        if not action_result:
            return None

        command_result: CommandResults = CommandResults(**action_result)
        return command_result

    def identity_search_command(self):
        response = self.client.identity_search()
        return self._process_result_actions(response=response)

    def identity_lookup_command(self):
        """Lookup command for identities"""
        response = self.client.identity_lookup()
        return self._process_result_actions(response=response)

    def password_lookup_command(self):
        """Lookup command for passwords"""
        response = self.client.password_lookup()
        return self._process_result_actions(response=response)


def main() -> None:
    """Main method used to run actions."""
    try:
        demisto_params = demisto.params()
        base_url = demisto_params.get("server_url", "").rstrip("/")
        verify_ssl = not demisto_params.get("unsecure", False)
        proxy = demisto_params.get("proxy", False)
        # If user has not set password properties we will get empty string but client require empty list

        headers = {
            "X-RFToken": demisto_params["token"],
            "X-RF-User-Agent": f"xsoar-identity/{__version__} rfclient (Cortex_XSOAR_"
            f'{demisto.demistoVersion()["version"]})',
        }
        client = Client(
            base_url=base_url,
            verify=verify_ssl,
            headers=headers,
            proxy=proxy,
        )
        command = demisto.command()
        actions = Actions(client)
        if command == "test-module":
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

    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command. " f"Error: {str(e)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
