"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

from datetime import datetime
import json
import io

from VaronisDataSecurityPlatform import SearchQueryBuilder, Client, get_query_range, get_search_result_path

ALERT_COLUMNS = [
    'Alert.ID',
    'Alert.Rule.Name'
]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# TODO: REMOVE the following dummy unit test function
def test_baseintegration_dummy():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """

    client = Client(verify=False)
    auth = client.varonis_authenticate('L1398\\administrator', 'p@ssword1')
    print(auth)
    print(client._headers)

    builder = SearchQueryBuilder(ALERT_COLUMNS, client)
    builder.create_alert_status_filter(['Open'])
    builder.create_threat_model_filter(['DNS'])
    builder.create_time_interval_filter(
        datetime.fromisoformat('2022-02-12T13:00:00+02:00'),
        datetime.fromisoformat('2022-02-12T13:59:00+02:00'))
    query = builder.build()
    print(json.dumps(query))
    response = client.varonis_search_alerts(query)
    location = get_search_result_path(response)
    print(location)
    range = get_query_range(10)
    search_result = client.varonis_get_alerts(location, range, 10)
    print(search_result)

    # args = {
    #     'dummy': 'this is a dummy response'
    # }
    # response = baseintegration_dummy_command(client, args)

    # mock_response = util_load_json('test_data/baseintegration-dummy.json')

    # assert response.outputs == mock_response
# TODO: ADD HERE unit tests for every command


test_baseintegration_dummy()
