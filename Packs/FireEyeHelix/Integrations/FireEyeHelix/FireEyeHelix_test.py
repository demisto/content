import pytest
from test_data.constants import (
    DICT_1to5,
    TRANS_DICT_134,
    DICT_NESTED_123,
    TRANS_DICT_NESTED_12,
    TRANS_DICT_NESTED_VAL_12,
    DICT_LST_AAB2B,
    TRANS_DICT_LST_A2B,
    DICT_LST_NESTED,
    TRANS_DICT_LST_NESTED,
)
from FireEyeHelix import (
    Client,
    build_search_groupby_result,
    list_alerts_command,
    get_alert_by_id_command,
    get_alert_notes_command,
    create_alert_note_command,
    get_events_by_alert_command,
    get_endpoints_by_alert_command,
    get_cases_by_alert_command,
    add_list_item_command,
    get_list_items_command,
    update_list_item_command,
    list_rules_command,
    edit_rule_command,
    search_command,
    archive_search_command,
    archive_search_status_command,
    archive_search_results_command,
    create_context_result,
    build_title_with_page_numbers,
)
from test_data.response_constants import (
    ALERT_RESP,
    ALERTS_RESP,
    SEARCH_AGGREGATIONS_SINGLE_RESP,
    SEARCH_AGGREGATIONS_MULTI_RESP,
    NOTES_GET_RESP,
    NOTES_CREATE_RESP,
    EVENTS_BY_ALERT_RESP,
    ENDPOINTS_BY_ALERT_RESP,
    CASES_BY_ALERT_RESP,
    LIST_ITEMS_RESP,
    LIST_SINGLE_ITEM_RESP,
    RULE_RESP,
    SEARCH_MULTI_RESP,
    SEARCH_ARCHIVE_RESP,
    SEARCH_ARCHIVE_RESULTS_RESP,
)
from test_data.result_constants import (
    EXPECTED_AGGREGATIONS_MULTI_RSLT,
    EXPECTED_AGGREGATIONS_SINGLE_RSLT,
    EXPECTED_ALERT_RSLT,
    EXPECTED_ALERTS_RSLT,
    EXPECTED_NOTES_GET_RSLT,
    EXPECTED_NOTES_CREATE_RSLT,
    EXPECTED_EVENTS_BY_ALERT_RSLT,
    EXPECTED_ENDPOINTS_BY_ALERT_RSLT,
    EXPECTED_CASES_NY_ALERT_RSLT,
    EXPECTED_SINGLE_LIST_ITEM_RSLT,
    EXPECTED_LIST_ITEMS_RSLT,
    EXPECTED_LIST_ITEMS_UPDATE_RSLT,
    EXPECTED_RULES_RSLT,
    EXPECTED_SEARCH_RSLT,
    EXPECTED_SEARCH_ARCHIVE_RSLT,
    EXPECTED_SEARCH_ARCHIVE_STATUS_RSLT,
    EXPECTED_SEARCH_ARCHIVE_RESULTS_RSLT,
    EXPECTED_RULE_RSLT,
)


def test_create_context_result_basic():
    assert create_context_result(DICT_1to5, TRANS_DICT_134) == {"one": 1, "three": 3, "four": 4}
    assert "one" not in DICT_1to5


def test_create_context_result_nested_keys():
    assert create_context_result(DICT_NESTED_123, TRANS_DICT_NESTED_12) == {"one": 1, "two": 2}


def test_create_context_result_nested_vals():
    assert create_context_result(DICT_1to5, TRANS_DICT_NESTED_VAL_12) == {"one": {"1": 1}, "two": 2}


def test_create_context_result_list():
    assert create_context_result(DICT_LST_AAB2B, TRANS_DICT_LST_A2B) == {"AaB": [{"two": 2}, {"two": 3}], "four": 4}
    assert create_context_result(DICT_LST_NESTED, TRANS_DICT_LST_NESTED) == {
        "Master": {"ID": 1, "Assets": [{"ID": 1, "Name": "a"}, {"ID": 2, "Name": "b"}]}
    }


def test_build_search_groupby_result():
    separator = "|%$,$%|"
    assert build_search_groupby_result(SEARCH_AGGREGATIONS_SINGLE_RESP, separator) == EXPECTED_AGGREGATIONS_SINGLE_RSLT
    assert build_search_groupby_result(SEARCH_AGGREGATIONS_MULTI_RESP, separator) == EXPECTED_AGGREGATIONS_MULTI_RSLT


def test_build_title_with_page_numbers_start():
    src_title = "Title"
    expected_title = "Title\n### Page 1/4"
    count = 100
    limit = 30
    offset = 0

    # start of first page
    assert expected_title == build_title_with_page_numbers(src_title, count, limit, offset)

    # end of first page
    offset = 24
    assert expected_title == build_title_with_page_numbers(src_title, count, limit, offset)


def test_build_title_with_page_numbers_last():
    src_title = "Title"
    expected_title = "Title\n### Page 4/4"
    count = 100
    limit = 30
    offset = 75

    # start of last page
    assert expected_title == build_title_with_page_numbers(src_title, count, limit, offset)

    offset = 101
    assert expected_title == build_title_with_page_numbers(src_title, count, limit, offset)


def test_build_title_with_page_numbers_wrong_type():
    src_title = "Title"
    count = "100"
    limit = 30
    offset = 0
    # count of wrong type
    assert src_title == build_title_with_page_numbers(src_title, count, limit, offset)

    # limit of wrong type
    count = 100
    limit = "30"
    assert src_title == build_title_with_page_numbers(src_title, count, limit, offset)

    # offset of wrong type
    limit = 30
    offset = "0"
    assert src_title == build_title_with_page_numbers(src_title, count, limit, offset)


def test_build_title_with_page_numbers_zero_div():
    src_title = "Title"
    count = 0
    limit = 30
    offset = 0
    assert src_title == build_title_with_page_numbers(src_title, count, limit, offset)


@pytest.mark.parametrize(
    "command,args,response,expected_result",
    [
        (list_alerts_command, {"page_size": 2}, ALERTS_RESP, EXPECTED_ALERTS_RSLT),
        (get_alert_by_id_command, {"id": 3232}, ALERT_RESP, EXPECTED_ALERT_RSLT),
        (get_alert_notes_command, {"id": 3232}, NOTES_GET_RESP, EXPECTED_NOTES_GET_RSLT),
        (
            create_alert_note_command,
            {"note": "This is a note test", "alert_id": 3232},
            NOTES_CREATE_RESP,
            EXPECTED_NOTES_CREATE_RSLT,
        ),
        (get_events_by_alert_command, {"alert_id": 3232}, EVENTS_BY_ALERT_RESP, EXPECTED_EVENTS_BY_ALERT_RSLT),
        (
            get_endpoints_by_alert_command,
            {"alert_id": 3232, "offset": 0},
            ENDPOINTS_BY_ALERT_RESP,
            EXPECTED_ENDPOINTS_BY_ALERT_RSLT,
        ),
        (
            get_cases_by_alert_command,
            {"alert_id": 3232, "offset": 0, "page_size": 1},
            CASES_BY_ALERT_RESP,
            EXPECTED_CASES_NY_ALERT_RSLT,
        ),
        (
            add_list_item_command,
            {"list_id": 3232, "value": "test", "type": "misc", "risk": "Low"},
            LIST_SINGLE_ITEM_RESP,
            EXPECTED_SINGLE_LIST_ITEM_RSLT,
        ),
        (get_list_items_command, {"list_id": 3232, "offset": 0}, LIST_ITEMS_RESP, EXPECTED_LIST_ITEMS_RSLT),
        (
            update_list_item_command,
            {"list_id": 3232, "value": "test", "type": "misc", "risk": "Low", "item_id": 163},
            LIST_SINGLE_ITEM_RESP,
            EXPECTED_LIST_ITEMS_UPDATE_RSLT,
        ),
        (list_rules_command, {"offset": 1}, RULE_RESP, EXPECTED_RULES_RSLT),
        (edit_rule_command, {"rule_id": "1.1.1", "enabled": "true"}, RULE_RESP, EXPECTED_RULE_RSLT),
        (
            search_command,
            {"query": "domain:google.com", "start": "4 days ago", "groupby": "subject", "limit": 1, "page_size": 2, "offset": 1},
            SEARCH_MULTI_RESP,
            EXPECTED_SEARCH_RSLT,
        ),
        (
            archive_search_command,
            {"query": "domain:google.com", "start": "4 days ago", "groupby": "subject", "limit": 1, "offset": 1},
            SEARCH_ARCHIVE_RESP,
            EXPECTED_SEARCH_ARCHIVE_RSLT,
        ),
        (archive_search_status_command, {"search_id": "82,83"}, SEARCH_ARCHIVE_RESP, EXPECTED_SEARCH_ARCHIVE_STATUS_RSLT),
        (archive_search_results_command, {"search_id": 82}, SEARCH_ARCHIVE_RESULTS_RESP, EXPECTED_SEARCH_ARCHIVE_RESULTS_RSLT),
    ],
)  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    headers = {"accept": "application/json", "x-fireeye-api-key": ""}
    client = Client(base_url="https://apps.fireeye.com/helix", verify=False, proxy=True, headers=headers)
    mocker.patch.object(client, "_http_request", return_value=response)
    res = command(client, args)
    assert expected_result == res[1]


def test_search_command_verify_args_passed_to_build_mql_query(mocker):
    """
    Given:
     - FireEye Helix integration client
     - `headers` argument given to the search command

    When:
     - Running the search command

    Then:
     - Ensure the command runs without raising exception that build_mql_query() got unexpected `headers` argument
    """
    args = {"headers": "bug1,bug2,toomanybugs"}
    client = Client(base_url="https://apps.fireeye.com/helix")
    mocker.patch.object(client, "_http_request", return_value={})
    search_command(client, args)
