import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServerPython.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes are defined.
    """

    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}


def test_module() -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set.'
        else:
            raise
    return message


def custom_indicator_creation(client: Client) -> CommandResults:
    # Command using a custom indicator example

    result = client.baseintegration_dummy("test")
    score = Common.DBotScore.GOOD
    indicator_value = 'custom_value'

    # Create a DBotScore object
    # Give it an indicator_type of DBotScoreType.CUSTOM
    dbot_score = Common.DBotScore(
        indicator=indicator_value,
        indicator_type=DBotScoreType.CUSTOM,
        integration_name='DummyIntegration',
        score=score,
    )
    # Create a data dictionary, which is the data of the indicator
    data = {
        'param1': 'value1',
        'param2': 'value2',
    }
    # Create the CustomIndicator
    custom_indicator = Common.CustomIndicator(
        indicator_type='MyCustomIndicator',
        dbot_score=dbot_score,
        value=indicator_value,
        data=data,
        context_prefix='custom',
    )
    # Return a CommandResults object containing the CustomIndicator object created
    return CommandResults(
        readable_output='custom_value',
        outputs=result,
        outputs_prefix='Demo.Result',
        outputs_key_field='test_key_field',
        indicator=custom_indicator,
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {}

        client = Client(
            base_url='',
            verify=False,
            headers=headers,
            proxy=False)

        if demisto.command() == 'test-module':
            result = test_module()
            return_results(result)
        elif demisto.command() == 'test-custom-indicator':
            return_results(custom_indicator_creation(client))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
