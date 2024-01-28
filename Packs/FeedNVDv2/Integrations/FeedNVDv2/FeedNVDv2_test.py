import json
import ast
from FeedNVDv2 import parse_cpe_command, retrieve_cves, build_indicators, Client
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


BASE_URL = "https://services.nvd.nist.gov"  # disable-secrets-detection


def get_test_data(command_name):
    """
    Retrieves data from specific files for unit testing

    Args:
        command_name: The command being tested

    Returns:
        The formatted data from the test data file
    """
    # Retrieve the raw CPE sample data
    if command_name == "test_parse_cpe_command":
        with open('./test_data/test_parse_cpe_command.txt') as f:
            # with open('./Packs/FeedNVDv2/Integrations/FeedNVDv2/test_data/test_parse_cpe_command.txt') as f:
            return f.read()
    # Retrieve the expected response to the sample CPE data
    elif command_name == "test_parse_cpe_command_response":
        with open('./test_data/test_parse_cpe_command_response.txt') as f:
            # with open('./Packs/FeedNVDv2/Integrations/FeedNVDv2/test_data/test_parse_cpe_command_response.txt') as f:
            return f.read()
    # Otherwise this is testing the CVE processing chain (retrieve_cves_command which calls process_cves_command)
    elif command_name == "test_retrieve_cves_command":
        with open('./test_data/test_retrieve_cves_response.json') as f:
            # with open('./Packs/FeedNVDv2/Integrations/FeedNVDv2/test_data/test_retrieve_cves_response.json') as f:
            return json.loads(f.read())
    elif command_name == "test_build_indicators_response":
        with open('./test_data/test_build_response.txt') as f:
            # with open('./Packs/FeedNVDv2/Integrations/FeedNVDv2/test_data/test_build_indicators_response.txt') as f:
            return json.loads(f.read())
    else:
        return "Error in test data retrieval"


def test_build_indicators_command():
    """
    Test function for the parse_cpe_command command

    Args:
        None

    Returns:
        Assertions if the tests fail for tag/relationship parsing of a CPE
    """
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        api_key='',
        tlp_color='',
        has_kev=None,
        start_date='1999-07-01',
        feed_tags=''
    )

    raw_cve = [get_test_data("test_retrieve_cves_command")]
    build_response = build_indicators(client, raw_cve)
    build_expected_response = get_test_data("test_build_indicators_response")

    assert all(item in build_expected_response[0] for item in build_response[0]), "BuildIndicators dictionaries are not equal"


def test_parse_cpe_command():
    """
    Test function for the parse_cpe_command command

    Args:
        None

    Returns:
        Assertions if the tests fail for tag/relationship parsing of a CPE
    """
    cpe_data = [get_test_data("test_parse_cpe_command")]
    responses = [get_test_data("test_parse_cpe_command_response")]

    tags, relationships = parse_cpe_command(cpe_data, "CVE-2021-44228")

    respList = [item.split('\n') for item in responses]
    tags_response, relationships_response = respList[0][0], respList[0][1]

    tags_response = ast.literal_eval(tags_response)
    relationships_response = ast.literal_eval(relationships_response)

    assert all(item in tags for item in tags_response), "Tag lists are not equal"
    assert all(item in relationships for item in relationships_response), "Relationship dictionaries are not equal"


def test_retrieve_cves_command():
    """
    Test function for the retrieve_cves_command command

    Args:
        None

    Returns:
        Assertions if the returned parsed indicator doesn't match the sample data
    """

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        api_key='',
        tlp_color='',
        has_kev=None,
        start_date='1999-07-01',
        feed_tags='')

    indicator = retrieve_cves(client, client.start_date, datetime.now(), True)
    response = [get_test_data("test_retrieve_cves_command")]

    assert all(item in indicator[0] for item in response[0]), "Indicator dictionary does not match expected response"


# if __name__ in ('__main__', '__builtin__', 'builtins'):
    # test_parse_cpe_command()
    # test_retrieve_cves_command()
    # test_build_indicators_command()
