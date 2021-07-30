import json
import urllib

DEHASHED_URL = "https://url.com/"  # disable-secrets-detection
INTEGRATION_CONTEXT_BRAND = "DeHashed"


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_module_command(requests_mock):
    """
    Given:
        - Performs a basic GET request to check if the API is reachable and authentication is successful.
    When
        - Setting a new instance of the integration.
    Then
        - returns "ok".
    """
    from DeHashed import Client, test_module

    test_data = load_test_data("test_data/search.json")
    url_params = {"query": 'vin:"test" "test1"'}
    encoded = urllib.parse.urlencode(url_params)

    requests_mock.get(f"{DEHASHED_URL}search?{encoded}", json=test_data["api_response"])

    client = Client(base_url=f"{DEHASHED_URL}", email='', api_key='')
    client._headers = {}
    res = test_module(client)

    assert res == "ok"


def test_search_command_using_is_operator_without_filter(requests_mock):
    """
    Given:
        - "Is" operator, value to search, and not using any filters.
    When
        - Searching an object that matches the specified value.
    Then
        - returns Demisto outputs.
    """
    from DeHashed import Client, dehashed_search_command

    test_data = load_test_data("test_data/search.json")
    expected_result = {
        "DeHashed.Search(val.Id==obj.Id)": test_data["expected_results"][
            "full_results"
        ],
        "DeHashed.LastQuery(true)": {
            "ResultsFrom": 1,
            "ResultsTo": 2,
            "DisplayedResults": 2,
            "TotalResults": 2,
            "PageNumber": 1
        },
    }
    url_params = {"query": '"testgamil.co"'}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f"{DEHASHED_URL}search?{encoded}", json=test_data["api_response"])

    client = Client(base_url=f"{DEHASHED_URL}", email='', api_key='')
    client._headers = {}
    markdown, context, raw = dehashed_search_command(client, test_data["is_op_single"])

    assert expected_result == context


def test_search_command_using_contains_operator_without_filter(requests_mock):
    """
    Given:
        - "Contains" operator, value to search.
    When
        - Searching an object that contains the specified value.
    Then
        - returns Demisto outputs.
    """
    from DeHashed import Client, dehashed_search_command

    test_data = load_test_data("test_data/search.json")
    expected_result = {
        "DeHashed.Search(val.Id==obj.Id)": test_data["expected_results"][
            "full_results"
        ],
        "DeHashed.LastQuery(true)": {
            "ResultsFrom": 1,
            "ResultsTo": 2,
            "DisplayedResults": 2,
            "TotalResults": 2,
            "PageNumber": 1
        },
    }
    url_params = {"query": "testgamil.co"}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f"{DEHASHED_URL}search?{encoded}", json=test_data["api_response"])

    client = Client(base_url=f"{DEHASHED_URL}", email='', api_key='')
    client._headers = {}
    markdown, context, raw = dehashed_search_command(
        client, test_data["contains_op_single"]
    )

    assert expected_result == context


def test_search_command_using_regex_operator_without_filter(requests_mock):
    """
    Given:
        - "Regex" operator, value to search.
    When
        - Searching an object that contains the specified value.
    Then
        - returns Demisto outputs.
    """
    from DeHashed import Client, dehashed_search_command

    test_data = load_test_data("test_data/search.json")
    expected_result = {
        "DeHashed.Search(val.Id==obj.Id)": test_data["expected_results"][
            "full_results"
        ],
        "DeHashed.LastQuery(true)": {
            "ResultsFrom": 1,
            "ResultsTo": 2,
            "DisplayedResults": 2,
            "TotalResults": 2,
            "PageNumber": 1
        },
    }
    url_params = {"query": "/joh?n(ath[oa]n)/"}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f"{DEHASHED_URL}search?{encoded}", json=test_data["api_response"])

    client = Client(base_url=f"{DEHASHED_URL}", email='', api_key='')
    client._headers = {}
    markdown, context, raw = dehashed_search_command(
        client, test_data["regex_op_single"]
    )

    assert expected_result == context


def test_search_command_using_is_operator_with_filter_and_multi_values(requests_mock):
    """
    Given:
        - "Is" operator, value to search and "email" as a filter.
    When
        - Searching an object that matches the specified value.
    Then
        - returns Demisto outputs.
    """
    from DeHashed import Client, dehashed_search_command

    test_data = load_test_data("test_data/search.json")
    expected_result = {
        "DeHashed.Search(val.Id==obj.Id)": test_data["expected_results"][
            "full_results"
        ],
        "DeHashed.LastQuery(true)": {
            "ResultsFrom": 1,
            "ResultsTo": 2,
            "DisplayedResults": 2,
            "TotalResults": 2,
            "PageNumber": 1
        },
    }
    url_params = {"query": 'email:"testgamil.co" "test1gmail.com"'}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f"{DEHASHED_URL}search?{encoded}", json=test_data["api_response"])

    client = Client(base_url=f"{DEHASHED_URL}", email='', api_key='')
    client._headers = {}
    markdown, context, raw = dehashed_search_command(client, test_data["is_op_multi"])

    assert expected_result == context


def test_search_command_using_contains_operator_with_filter_and_multi_values(
    requests_mock,
):
    """
    Given:
        - "Contains" operator, value to search and "name" as a filter.
    When
        - Searching an object that contains the specified value.
    Then
        - returns Demisto outputs.
    """
    from DeHashed import Client, dehashed_search_command

    test_data = load_test_data("test_data/search.json")
    expected_result = {
        "DeHashed.Search(val.Id==obj.Id)": test_data["expected_results"][
            "full_results"
        ],
        "DeHashed.LastQuery(true)": {
            "ResultsFrom": 1,
            "ResultsTo": 2,
            "DisplayedResults": 2,
            "TotalResults": 2,
            "PageNumber": 1
        },
    }
    url_params = {"query": "name:(test1 OR test2)"}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f"{DEHASHED_URL}search?{encoded}", json=test_data["api_response"])

    client = Client(base_url=f"{DEHASHED_URL}", email='', api_key='')
    client._headers = {}
    markdown, context, raw = dehashed_search_command(
        client, test_data["contains_op_multi"]
    )

    assert expected_result == context


def test_search_command_using_regex_operator_with_filter_and_multi_values(
    requests_mock,
):
    """
    Given:
        - "Regex" operator, value to search and "vin" as a filter.
    When
        - Searching an object that contains the specified value.
    Then
        - returns Demisto outputs.
    """
    from DeHashed import Client, dehashed_search_command

    test_data = load_test_data("test_data/search.json")
    expected_result = {
        "DeHashed.Search(val.Id==obj.Id)": test_data["expected_results"][
            "full_results"
        ],
        "DeHashed.LastQuery(true)": {
            "ResultsFrom": 1,
            "ResultsTo": 2,
            "DisplayedResults": 2,
            "TotalResults": 2,
            "PageNumber": 1
        },
    }
    url_params = {"query": "vin:/joh?n(ath[oa]n)/ /joh?n11(ath[oa]n)/"}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f"{DEHASHED_URL}search?{encoded}", json=test_data["api_response"])

    client = Client(base_url=f"{DEHASHED_URL}", email='', api_key='')
    client._headers = {}
    markdown, context, raw = dehashed_search_command(
        client, test_data["regex_op_multi"]
    )

    assert expected_result == context


def test_search_command_using_regex_operator_with_filter_and_change_result_range(
    requests_mock,
):
    """
    Given:
        - "Regex" operator, value to search, "vin" as a filter and a range of results amount to return.
    When
        - Searching an object that contains the specified value.
    Then
        - returns Demisto outputs.
    """
    from DeHashed import Client, dehashed_search_command

    test_data = load_test_data("test_data/search.json")
    expected_result = {
        "DeHashed.Search(val.Id==obj.Id)": test_data["expected_results_range"][
            "full_results"
        ],
        "DeHashed.LastQuery(true)": {
            "ResultsFrom": 1,
            "ResultsTo": 1,
            "DisplayedResults": 1,
            "TotalResults": 2,
            "PageNumber": 1
        },
    }
    url_params = {"query": "vin:/joh?n(ath[oa]n)/ /joh?n11(ath[oa]n)/"}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f"{DEHASHED_URL}search?{encoded}", json=test_data["api_response"])

    client = Client(base_url=f"{DEHASHED_URL}", email='', api_key='')
    client._headers = {}
    markdown, context, raw = dehashed_search_command(
        client, test_data["regex_op_multi_range"]
    )

    assert expected_result == context


def test_email_command_malicious_dbot_score(mocker):
    """
    Given:
        - The email address to check and that user defined the default dbot score to be 'MALICIOUS'.
    When:
        - Searching an object that contains the given email address.
    Then:
        - Return the demisto outputs and validate that the dbot score is malicious.
    """
    from DeHashed import Client, email_command

    test_data = load_test_data('test_data/search.json')
    expected_result = {
        'DeHashed.Search(val.Id==obj.Id)': test_data['expected_results'][
            'full_results'
        ],
        'DBotScore': {
            'Indicator': 'testgamil.com',
            'Type': 'email',
            'Vendor': 'DeHashed',
            'Score': 3
        }
    }
    client = Client(base_url=f'{DEHASHED_URL}', email_dbot_score='MALICIOUS', email='', api_key='')
    mocker.patch.object(client, 'dehashed_search', return_value=test_data['api_response'])
    markdown, context, raw = email_command(client, test_data['email_command'])

    assert expected_result == context


def test_email_command_suspicious_dbot_score(mocker):
    """
    Given:
        - The email address to check and that user defined the default dbot score to be 'SUSPICIOUS'.
    When:
        - Searching an object that contains the given email address.
    Then:
        - Return the demisto outputs and validate that the dbot score is suspicious.
    """
    from DeHashed import Client, email_command

    test_data = load_test_data('test_data/search.json')
    expected_result = {
        'DeHashed.Search(val.Id==obj.Id)': test_data['expected_results'][
            'full_results'
        ],
        'DBotScore': {
            'Indicator': 'testgamil.com',
            'Type': 'email',
            'Vendor': 'DeHashed',
            'Score': 2
        }
    }
    client = Client(base_url=f'{DEHASHED_URL}', email_dbot_score='SUSPICIOUS', email='', api_key='')
    mocker.patch.object(client, 'dehashed_search', return_value=test_data['api_response'])
    markdown, context, raw = email_command(client, test_data['email_command'])

    assert expected_result == context


def test_email_command_no_entries_returned(mocker):
    """
    Given:
        - The email address to check.
    When:
        - Searching an object that contains the given email address and no results are returned.
    Then:
        - Validate that the DBotScore is set to 0.
    """
    from DeHashed import Client, email_command

    test_data = load_test_data('test_data/search.json')
    expected_result = {
        'DBotScore': {
            'Indicator': 'testgamil.com',
            'Type': 'email',
            'Vendor': 'DeHashed',
            'Score': 0
        }
    }
    client = Client(base_url=f'{DEHASHED_URL}', email='', api_key='')
    mocker.patch.object(client, 'dehashed_search', return_value={})
    markdown, context, raw = email_command(client, test_data['email_command'])

    assert expected_result == context
