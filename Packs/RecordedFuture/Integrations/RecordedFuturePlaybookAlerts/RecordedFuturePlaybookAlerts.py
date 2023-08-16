import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Recorded Future Playbook alerts Integration for Demisto."""

import platform
import json
import base64

# flake8: noqa: F402,F405 lgtm

STATUS_TO_RETRY = [500, 501, 502, 503, 504]

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore

__version__ = '1.0.2'


# === === === === === === === === === === === === === === ===
# === === === === Recorded Future API Client === === === ====
# === === === === === === === === === === === === === === ===


class Client(BaseClient):
    def whoami(self) -> Dict[str, Any]:

        return self._http_request(
            method='get',
            url_suffix='info/whoami',
            timeout=60,
        )

    def _call(self, url_suffix, **kwargs):

        json_data = {
            'demisto_command': demisto.command(),
            'demisto_args': demisto.args(),
        }
        if 'demisto_args' in kwargs.keys():
            if args := kwargs.get('demisto_args'):
                json_data.update({'demisto_args': args})
            kwargs.pop('demisto_args')

        method = kwargs.get('method', 'post')

        request_kwargs = {
            'method': method,
            'url_suffix': url_suffix,
            'json_data': json_data,
            'timeout': 90,
            'retries': 3,
            'status_list_to_retry': STATUS_TO_RETRY,
        }

        request_kwargs.update(kwargs)

        try:
            response = self._http_request(**request_kwargs)

            if isinstance(response, dict) and response.get('return_error'):
                # This will raise the Exception or call "demisto.results()" for the error and sys.exit(0).
                return_error(**response['return_error'])

        except DemistoException as err:
            if '404' in str(err):
                return CommandResults(
                    outputs_prefix='',
                    outputs=dict(),
                    raw_response=dict(),
                    readable_output='No results found.',
                    outputs_key_field='',
                )
            else:
                raise err

        return response

    def fetch_incidents(self) -> Dict[str, Any]:
        """Fetch incidents."""
        return self._call(
            url_suffix=f'/v2/playbook_alert/fetch',
            json_data={
                'demisto_command': demisto.command(),
                'demisto_args': demisto.args(),
                'demisto_params': demisto.params(),
                'demisto_last_run': demisto.getLastRun(),
            },
            timeout=120,
        )

    #######################################################
    ################## Playbook alerts ####################
    #######################################################

    def details_playbook_alerts(self) -> Dict[str, Any]:
        parsed_args = demisto.args()
        if alert_ids := parsed_args.get('alert_ids'):
            parsed_args['alert_ids'] = alert_ids.split(",")
        if sections := parsed_args.get('detail_sections'):
            parsed_args["detail_sections"] = sections.split(",")
        """Get details of a playbook alert"""
        return self._call(
            url_suffix='/v2/playbook_alert/lookup', demisto_args=parsed_args
        )

    def update_playbook_alerts(self) -> Dict[str, Any]:
        parsed_args = demisto.args()
        if ids := parsed_args.get('alert_ids'):
            parsed_args["alert_ids"] = ids.split(",")
        return self._call(
            url_suffix='/v2/playbook_alert/update', demisto_args=parsed_args
        )

    def search_playbook_alerts(self) -> Dict[str, Any]:
        parsed_args = demisto.args()
        if categories := parsed_args.get('category'):
            parsed_args["category"] = categories.split(",")
        if statuses := parsed_args.get('playbook_alert_status'):
            parsed_args["playbook_alert_status"] = statuses.split(",")
        return self._call(
            url_suffix='/v2/playbook_alert/search', demisto_args=parsed_args
        )


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

        result_actions: Union[List[dict], None] = response.get('result_actions')

        if not result_actions:
            return None  # type: ignore

        command_results: List[CommandResults] = list()
        for action in result_actions:
            if 'CommandResults' in action:
                command_results.append(CommandResults(**action['CommandResults']))

        return command_results

    def fetch_incidents(self) -> None:

        response = self.client.fetch_incidents()

        if isinstance(response, CommandResults):
            # 404 case.
            return

        for _key, _val in response.items():
            if _key == 'demisto_last_run':
                demisto.setLastRun(_val)
            if _key == 'incidents':
                for incident in _val:
                    attachments = list()
                    incident_json = json.loads(incident.get("rawJSON", "{}"))
                    if incident_json.get("panel_evidence_summary", {}).get(
                        "screenshots"
                    ):
                        for screenshot_data in incident_json["panel_evidence_summary"][
                            "screenshots"
                        ]:
                            file_name = f'{screenshot_data.get("image_id", "").replace("img:","")}.png'
                            file_data = screenshot_data.get("base64", "")
                            file = fileResult(file_name, base64.b64decode(file_data))
                            attachment = {
                                "description": screenshot_data.get('description'),
                                "name": file.get("File"),
                                "path": file.get("FileID"),
                                "showMediaFile": True,
                            }
                            attachments.append(attachment)
                        incident['attachment'] = attachments

                demisto.incidents(_val)

        #######################################################
        ################## Playbook alerts ####################
        #######################################################

    def playbook_alert_details_command(self) -> List[CommandResults]:
        response = self.client.details_playbook_alerts()
        return self._process_result_actions(response=response)

    def playbook_alert_update_command(self) -> List[CommandResults]:
        response = self.client.update_playbook_alerts()
        return self._process_result_actions(response=response)

    def playbook_alert_search_command(self) -> List[CommandResults]:
        response = self.client.search_playbook_alerts()
        return self._process_result_actions(response=response)


# === === === === === === === === === === === === === === ===
# === === === === === === === MAIN === === === === === === ==
# === === === === === === === === === === === === === === ===


def main() -> None:
    """Main method used to run actions."""
    try:
        demisto_params = demisto.params()
        base_url = demisto_params.get('server_url', '').rstrip('/')
        verify_ssl = not demisto_params.get('insecure', False)
        proxy = demisto_params.get('proxy', False)

        headers = {
            'X-RFToken': demisto_params['token'].get('password'),
            'X-RF-User-Agent': (
                f'RecordedFuturePlaybookAlerts.py/{__version__} ({platform.platform()}) '
                f'XSOAR/{__version__} '
                f'RFClient/{__version__} (Cortex_XSOAR_{demisto.demistoVersion()["version"]})'
            ),
        }
        client = Client(
            base_url=base_url, verify=verify_ssl, headers=headers, proxy=proxy
        )
        command = demisto.command()
        actions = Actions(client)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            # Returning 'ok' indicates that the integration works like it suppose to and
            # connection to the service is successful.
            # Returning 'ok' will make the test result be green.
            # Any other response will make the test result be red.

            try:
                client.whoami()
                return_results('ok')
            except Exception as err:
                message = str(err)
                try:
                    error = json.loads(str(err).split('\n')[1])
                    if 'fail' in error.get('result', dict()).get('status', ''):
                        message = error.get('result', dict())['message']
                except Exception:
                    message = (
                        'Unknown error. Please verify that the API'
                        f' URL and Token are correctly configured. RAW Error: {err}'
                    )
                raise DemistoException(f'Failed due to - {message}')

        elif command == 'fetch-incidents':
            actions.fetch_incidents()

        #######################################################
        ################## Playbook alerts ####################
        #######################################################

        elif command == 'recordedfuture-playbook-alerts-details':
            return_results(actions.playbook_alert_details_command())

        elif command == 'recordedfuture-playbook-alerts-update':
            return_results(actions.playbook_alert_update_command())

        elif command == 'recordedfuture-playbook-alerts-search':
            return_results(actions.playbook_alert_search_command())

    except Exception as e:
        return_error(message=f'Failed to execute {demisto.command()} command: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
