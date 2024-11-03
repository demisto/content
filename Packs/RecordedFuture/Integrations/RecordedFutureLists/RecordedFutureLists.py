import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Recorded Future Lists Integration for Demisto."""

import platform
import json

# flake8: noqa: F402,F405 lgtm

STATUS_TO_RETRY = [500, 501, 502, 503, 504]

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore

__version__ = '1.1.1'


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
        if 'demisto_args' in kwargs:
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

    ####################################################
    ################## List operations #################
    ####################################################

    def list_search(self) -> Dict[str, Any]:
        parsed_args = demisto.args()
        if list_names := parsed_args.get('list_names'):
            parsed_args['list_names'] = list_names.split(",")
        if types := parsed_args.get('contains'):
            parsed_args["contains"] = types.split(",")
        """Search for lists in Recorded Future"""
        return self._call(url_suffix='/v2/lists/search', demisto_args=parsed_args)

    ####################################################
    ################ Entity operations #################
    ####################################################

    def entity_operation(self, operation) -> Dict[str, Any]:
        parsed_args = demisto.args()

        list_id = parsed_args.pop("list_id")

        if entity_ids := parsed_args.get('entity_ids'):
            parsed_args["entity_ids"] = entity_ids.split(",")

        if freetext_names := parsed_args.get('freetext_names'):
            parsed_args["freetext_names"] = freetext_names.split(",")

        if not (
            (entity_ids and not freetext_names) or (not entity_ids and freetext_names)
        ):  # XOR entity_ids and freetext_names
            raise ValueError(
                "Command expected 1 of parmeters: entity_ids or freetext_names, to be specified."
                f" Got {len([x for x in [entity_ids, freetext_names] if x])} specified."
            )

        return self._call(
            url_suffix=f'/v2/lists/{list_id}/entities/{operation}',
            demisto_args=parsed_args,
        )

    def entity_fetch(self) -> Dict[str, Any]:
        parsed_args = demisto.args()
        if list_ids := parsed_args.get("list_ids"):
            parsed_args["list_ids"] = list_ids.split(",")
        return self._call(
            url_suffix='/v2/lists/entities/lookup', demisto_args=parsed_args
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

        #######################################################
        #################### List actions #####################
        #######################################################

    def list_search_command(self) -> List[CommandResults]:
        response = self.client.list_search()
        return self._process_result_actions(response=response)

        #######################################################
        ################### Entity actions ####################
        #######################################################

    def entity_add_command(self) -> List[CommandResults]:
        response = self.client.entity_operation("add")
        return self._process_result_actions(response=response)

    def entity_remove_command(self) -> List[CommandResults]:
        response = self.client.entity_operation("remove")
        return self._process_result_actions(response=response)

    def entities_get_command(self) -> List[CommandResults]:
        response = self.client.entity_fetch()
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
                f'RecordedFutureLists.py/{__version__} ({platform.platform()}) '
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

        #######################################################
        ################### List commands #####################
        #######################################################

        elif command == 'recordedfuture-lists-search':
            return_results(actions.list_search_command())
        #######################################################
        ################## Entity commands ####################
        #######################################################

        elif command == 'recordedfuture-lists-add-entities':
            return_results(actions.entity_add_command())

        elif command == 'recordedfuture-lists-remove-entities':
            return_results(actions.entity_remove_command())

        elif command == 'recordedfuture-lists-entities':
            return_results(actions.entities_get_command())

    except Exception as e:
        return_error(message=f'Failed to execute {demisto.command()} command: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
