import pytest

from CommonServerPython import *
import demistomock as demisto


@pytest.mark.parametrize(
    "return_val, expected",
    [
        (None, None),
        (["1.1.1.1"], ["1.1.1.1"]),
        (["1.1.1.1", "2.2.2.2"], ["1.1.1.1", "2.2.2.2"]),
    ],
)
def test_get_contents(mocker, return_val, expected):
    """
    Given:
        - All relevant arguments are passed
    When:
        - abuseipdb-get-blacklist command is executed in get_contents function
    Then:
        - Check if get_contents return value is valid
    """
    from AbuseIPDBPopulateIndicators import get_contents

    mocker.patch("AbuseIPDBPopulateIndicators.execute_command", return_value=return_val)
    assert get_contents({}) == expected


@pytest.mark.parametrize("input", ["Too many requests", None])
def test_check_ips_fail(input):
    """
    Given:
        - Invalid argument is passed
    When:
        - check_ips function is executed
    Then:
        - Raise DemistoException
    """
    from AbuseIPDBPopulateIndicators import check_ips

    with pytest.raises(DemistoException) as e:
        check_ips(input)
    assert str(e.value) == "No Indicators were created (possibly bad API key)"


def test_check_ips():
    """
    Given:
        - Valid argument is passed
    When:
        - check_ips function is executed
    Then:
        - Return None
    """
    from AbuseIPDBPopulateIndicators import check_ips

    assert check_ips(["1.1.1.1"]) is None


def test_main(mocker):
    """
    Given:
        - All return values from helper functions are valid
    When:
        - main function is executed
    Then:
        - Return results to War-Room
    """
    from AbuseIPDBPopulateIndicators import main

    mocker.patch.object(
        demisto, "args", return_value={"days": 30, "limit": 200, "confidence": 100}
    )
    mocker.patch("AbuseIPDBPopulateIndicators.execute_command", return_value=None)
    mocker.patch("AbuseIPDBPopulateIndicators.get_contents", return_value=["1.1.1.1"])
    return_results_mock = mocker.patch("AbuseIPDBPopulateIndicators.return_results")
    main()
    return_results_mock.assert_called_with("All Indicators were created successfully")
