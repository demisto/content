"""ListUsedDockersImages for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all functions names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

"""


def util_get_content(file_name: str) -> dict:
    with open(file_name) as fp:
        content = fp.read()
        fp.close()
    return content


def test_api_response_parsing():
    """
        Tests REST API responses parsing content.
    """
    from ListUsedDockerImages import extract_dockers_from_automation_search_result, \
        extract_dockers_from_integration_search_result, merge_result, MAX_PER_DOCKER, format_result_for_markdown

    integration_response = extract_dockers_from_integration_search_result(
        util_get_content('test_data/integration_search_response.json'))
    automation_response = extract_dockers_from_automation_search_result(
        util_get_content('test_data/automation_search_response.json'))

    assert len(integration_response) == 4 or len(automation_response) == 162

    result_dict = {}
    result_dict = merge_result(integration_response, result_dict, MAX_PER_DOCKER)
    result_dict = merge_result(automation_response, result_dict, MAX_PER_DOCKER)

    assert len(result_dict) == 62

    result_str = format_result_for_markdown(result_dict)

    assert len(result_dict) == len(result_str)
