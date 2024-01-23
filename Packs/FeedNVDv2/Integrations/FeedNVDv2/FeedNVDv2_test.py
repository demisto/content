import json
import ast
from FeedNVDv2 import retrieve_cves_command, parse_cpe_command
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
    if command_name == "parse_cpe_command":
        # with open('./test_data/test_cpe_data.txt') as f:
        with open('./test_data/test_cpe_data.txt') as f:
            return f.read()
    # Retrieve the expected response to the sample CPE data
    elif command_name == "parse_cpe_command_response":
        # with open('./test_data/test_cpe_data_response.txt') as f:
        with open('./test_data/test_cpe_data_response.txt') as f:
            return f.read()
    # Otherwise this is testing the CVE processing chain (retrieve_cves_command which calls process_cves_command)
    else:
        # with open('./test_data/test_cve_data_response.json') as f:
        with open('./test_data/test_cve_data_response.json') as f:
            return json.loads(f.read())


def test_parse_cpe_command():
    """
    Test function for the parse_cpe_command command

    Args:
        None

    Returns:
        Assertions if the tests fail for tag/relationship parsing of a CPE
    """
    cpe_data = [get_test_data("parse_cpe_command")]
    responses = [get_test_data("parse_cpe_command_response")]

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
    params = {
      'cpeName': None,
      'cvssV2Metrics': None,
      'cvssV2Severity': None,
      'cvssV3Metrics': None,
      'cvssV3Severity': None,
      'hasCertAlerts': False,
      'hasKev': False,
      'isVulnerable': False,
      'keywordSearch': None,
      'keywordExactMatch': False,
      'lastModStartDate': None,
      'lastModEndDate': None,
      'pubStartDate': None,
      'pubEndDate': None,
      'noRejected': None,
      'start_date': '2021-11-01',
      'insecure': 'True',
      'proxy': 'False',
      'feedTags': '',
      'apiKey': {'identifier': '',
                'password': '380c5f21-2256-47b8-a43a-6080e445cf39'}
    }
    client = BaseClient(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
    )

    indicator = retrieve_cves_command(client, params, True)
    response = [get_test_data("test_cve_processing")]

    assert all(item in indicator[0] for item in response[0]), "Indicator dictionary does not match expected response"


"""if __name__ in ('__main__', '__builtin__', 'builtins'):
    # test_parse_cpe_command()
    test_retrieve_cves_command()"""
