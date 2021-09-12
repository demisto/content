"""ListUsedDockersImages for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all functions names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

"""

import json
import io

def util_get_content(file_name :str) -> dict:
    with open(file_name) as fp:
        content = fp.read()
        fp.close()
    return content


def test_api_response_parsing():
    """
        Tests REST API responses parsing content.
    """
    from ListUsedDockersImages import extract_dockers_from_automation_search_result, \
        extract_dockers_from_integration_search_result
    integration_response = extract_dockers_from_integration_search_result(
        util_get_content('test_data/integration_search_response.json'))
    automation_response = extract_dockers_from_automation_search_result(
        util_get_content('test_data/automation_search_response.json'))

    assert len(integration_response) == 29 or len(integration_response) == 226
