from CommonServerPython import *
import pytest
from CarbonBlackProtect import main
import demistomock as demisto


@pytest.mark.parametrize(
    "params, expected_result",
    [
        ({"url": "https://ec2.us.compute-1.amazonaws.com"}, "API Token must be provided."),
    ],
)
def test_params(mocker, params, expected_result):
    """
    Given:
      - Configuration parameters
    When:
      - One of the required parameters are missed.
    Then:
      - Ensure the exception message as expected.
    """
    mocker.patch.object(demisto, "params", return_value=params)

    with pytest.raises(Exception) as e:
        main()

    assert expected_result in str(e.value)


def test_remove_prefix():
    from CarbonBlackProtect import remove_prefix

    prefix = "test_prefix"

    str_with_prefix = "{}a".format(prefix)
    expected_response = "a"
    assert remove_prefix(prefix, str_with_prefix) == expected_response

    str_without_prefix = "b{}".format(prefix)
    expected_response = str_without_prefix
    assert remove_prefix(prefix, str_without_prefix) == expected_response

    str_with_two_prefixes = "{prefix}{prefix}c".format(prefix=prefix)
    expected_response = "{}c".format(prefix)
    assert remove_prefix(prefix, str_with_two_prefixes) == expected_response


def test_event_severity_to_dbot_score():
    malicious_scores = (2,)
    warning_scores = (4, 5)
    unknown_scores = (3, "6", 7)

    assert_score(malicious_scores, 3)
    assert_score(warning_scores, 2)
    assert_score(unknown_scores, 0)


def test_cbp_date_to_timestamp():
    from CarbonBlackProtect import cbp_date_to_timestamp

    cbp_time_with_milis = "2019-04-19T15:20:42.000000Z"
    expected_ts = date_to_timestamp(cbp_time_with_milis, date_format="%Y-%m-%dT%H:%M:%S.%fZ")
    assert cbp_date_to_timestamp(cbp_time_with_milis) == expected_ts

    cbp_time_without_milis = "2019-04-19T15:20:42Z"
    expected_ts = date_to_timestamp(cbp_time_without_milis, date_format="%Y-%m-%dT%H:%M:%SZ")
    assert cbp_date_to_timestamp(cbp_time_without_milis) == expected_ts

    try:
        non_cbp_time = "20-04-2019T15:20:42"
        cbp_date_to_timestamp(non_cbp_time)
        raise AssertionError("cbp_date_to_timestamp should fail when passing non-cbp format dates")
    except ValueError:
        # if got here, then the right error was passed, so no further checks are required
        pass


def test_remove_keys_with_empty_value():
    from CarbonBlackProtect import remove_keys_with_empty_value

    base_dict = {"first": 1, "second": 2}
    assert remove_keys_with_empty_value(base_dict) == base_dict

    dict_with_empty_value = dict(base_dict)
    dict_with_empty_value["third"] = None
    dict_with_empty_value["fourth"] = ""
    assert remove_keys_with_empty_value(dict_with_empty_value) == base_dict


def assert_score(severity_tuple, expected_output):
    from CarbonBlackProtect import event_severity_to_dbot_score

    for severity in severity_tuple:
        assert event_severity_to_dbot_score(severity) == expected_output
