"""SEKOIA.IO Integration for Cortex XSOAR (aka Demisto)
"""
import demistomock as demisto
from CommonServerPython import *
import urllib3
import traceback
from typing import Any, Dict


# Disable insecure warnings
urllib3.disable_warnings()

DOC_MAPPING = {
    "GetObservable": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Observables/operation/get_observables",  # noqa
    "GetIndicator": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Indicators/operation/get_indicator",  # noqa
    "GetIndicatorContext": "https://docs.sekoia.io/develop/rest_api/intelligence_center/intelligence/#tag/Indicators/operation/get_indicator_context",  # noqa
}

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the SEKOIA.IO API"""

    def get_validate_resource(self):
        return self._http_request(
            method="GET",
            url_suffix="/v1/apiauth/auth/validate",
        )

    def get_observables(self, value: str, indicator_type: str):
        """Find indicators matching the given value

        :type value: ``str``
        :param value: indicator to get the context for

        :type indicator_type: ``str``
        :param indicator_type: type of the indicator

        :return: dict containing the context as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method="GET",
            url_suffix="/v2/inthreat/observables",
            params={"match[value]": value, "match[type]": indicator_type},
        )

    """Client class to interact with the SEKOIA.IO API"""

    def get_indicator(self, value: str, indicator_type: str):
        """Find indicators matching the given value

        :type value: ``str``
        :param value: indicator to get the context for

        :type indicator_type: ``str``
        :param indicator_type: type of the indicator

        :return: dict containing the context as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method="GET",
            url_suffix="/v2/inthreat/indicators",
            params={"value": value, "type": indicator_type},
        )

    def get_indicator_context(self, value: str, indicator_type: str):
        """Get context around the indicators matching the given value

        :type value: ``str``
        :param value: indicator to get the context for

        :type type: ``str``
        :param type: type of the indicator

        :return: dict containing the context as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method="GET",
            url_suffix="/v2/inthreat/indicators/context",
            params={"value": value, "type": indicator_type},
        )


""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: Client

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    # Check a JWT token’s validity
    # https://docs.sekoia.io/develop/rest_api/identity_and_authentication/#tag/User-Authentication/operation/get_validate_resource

    try:
        client.get_validate_resource()
    except DemistoException as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


def get_indicator_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ip command: Returns IP reputation for a list of IPs

    :type client: ``Client``
    :param Client: SEKOIA.IO client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['indicator']`` is a list of indicators or a single indicator

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains indicators

    :rtype: ``CommandResults``
    """

    indicator_value = args.get("value")
    indicator_type = args.get("type")
    if not indicator_value or not indicator_type:
        raise ValueError(f"incomplete command for value {indicator_value} and type {indicator_type}")

    result = client.get_indicator(value=indicator_value, indicator_type=indicator_type)
    indicator = {"value": indicator_value, "type": indicator_type}
    outputs = {"indicator": indicator, "items": result.get("items", [])}

    # Format output
    if result["items"] == []:
        markdown = f"### {indicator_value} of type {indicator_type} is an unknown indicator."
    else:
        markdown = f'### Indicator {result["items"][0].get("name")} is categorized as {result["items"][0].get("indicator_types")}\n\n'
        markdown += result["items"][0].get("description", "")
        table_headers = ['kill_chain_name', 'phase_name']
        markdown += tableToMarkdown("Kill chain", result["items"][0].get('kill_chain_phases'), headers=table_headers)
        markdown += f'\n\nPlease consult the [dedicated page](https://app.sekoia.io/intelligence/objects/{result["items"][0]["id"]}) for more information.\n'


    return CommandResults(
        outputs_prefix="SEKOIA.Analysis",
        outputs=outputs,
        readable_output=markdown,
        raw_response=result
    )


def get_indicator_context_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ip command: Returns IP reputation for a list of IPs

    :type client: ``Client``
    :param Client: SEKOIA.IO client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['indicator']`` is a list of indicators or a single indicator

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains indicators

    :rtype: ``CommandResults``
    """

    indicator_value = args.get("value")
    indicator_type = args.get("type")
    if not indicator_value or not indicator_type:
        raise ValueError(f"incomplete command for value {indicator_value} and type {indicator_type}")

    result = client.get_indicator_context(value=indicator_value, indicator_type=indicator_type)
    indicator = {"value": indicator_value, "type": indicator_type}
    outputs = {"indicator": indicator, "items": result.get("items", [])}

    # Format output
    if result["items"] == []:
        markdown = f"### {indicator_value} of type {indicator_type} is an unknown indicator."
    else:
        markdown = f'### This indicator is associated to {result["items"][0]["objects"][1].get("name")} also known as {result["items"][0]["objects"][1].get("aliases")}\n\n'
        markdown += result["items"][0]["objects"][1].get("description")
        table_headers = ['description', 'source_name', 'url']
        markdown += tableToMarkdown("External references", result["items"][0]['objects'][1].get('external_references'), headers=table_headers)
        markdown += f'\n\nPlease consult the [dedicated page](https://app.sekoia.io/intelligence/objects/{result["items"][0]["id"]}) for more information.\n'

    return CommandResults(
        outputs_prefix="SEKOIAIO.IndicatorContext",
        readable_output=markdown,
        outputs=outputs,
        raw_response=result
    )


def get_observables_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ip command: Returns IP reputation for a list of IPs

    :type client: ``Client``
    :param Client: SEKOIA.IO client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['indicator']`` is a list of indicators or a single indicator

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains indicators

    :rtype: ``CommandResults``
    """

    indicator_value = args.get("value")
    indicator_type = args.get("type")
    if not indicator_value or not indicator_type:
        raise ValueError(f"incomplete command for value {indicator_value} and type {indicator_type}")

    result = client.get_observables(value=indicator_value, indicator_type=indicator_type)
    indicator = {"value": indicator_value, "type": indicator_type}
    outputs = {"indicator": indicator, "items": result.get("items", [])}

    
    if result["items"] == []:
        markdown = f"### {indicator_value} of type {indicator_type} is an unknown observable."
    else:
        table_title = f'Observable {result["items"][0].get("value")}'
        table_headers = ['modified', 'created']
        markdown = tableToMarkdown(table_title, result["items"][0], headers=table_headers)
        table_headers = ['valid_from', 'valid_until', 'name']
        markdown += tableToMarkdown("Associated tags", result["items"][0].get('x_inthreat_tags'), headers=table_headers)
        markdown += f'Please consult the [dedicated page](https://app.sekoia.io/intelligence/objects/{result["items"][0]["id"]}) for more information.\n'


    return CommandResults(
        readable_output=markdown,
        outputs_prefix="SEKOIAIO.Observable",
        outputs_key_field="ip",
        outputs=outputs,
    )


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get("apikey")
    if not api_key:
        demisto.error("API Key is missing")

    # get the service API url
    base_url = urljoin(demisto.params()["url"], "/")
    verify_certificate = not demisto.params().get("insecure", False)

    # How much time before the first fetch to retrieve incidents

    proxy = demisto.params().get("proxy", False)

    # TODO
    # Integration that implements reputation commands (e.g. url, ip, domain,..., etc) must have
    # a reliability score of the source providing the intelligence data.
    # reliability = demisto.params().get('integrationReliability', DBotScoreReliability.C)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}

        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            # https://api.sekoia.io/v1/apiauth/auth/validate
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "GetObservable":
            return_results(get_observables_command(client, demisto.args()))

        elif demisto.command() == "GetIndicator":
            return_results(get_indicator_command(client, demisto.args()))

        elif demisto.command() == "GetIndicatorContext":
            return_results(get_indicator_context_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command. "
            f"\nError:\n{str(e)} please consult endpoint documentation {DOC_MAPPING.get(demisto.command())}"
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
