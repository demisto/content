import demistomock as demisto
import pytest
from GetDataCollectionLink import (
    encode_string,
    get_data_collection_url,
    is_machine_saas,
    generate_url,
)


def test_main(mocker):
    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"platform": "xsoar", "version": "6.12.0"},
    )
    assert encode_string("abcde") == "59574a6a5a47553d"
    assert get_data_collection_url("1", ["t"]) == [
        {
            "task": "1@1",
            "url": "https://test-address:8443/#/external/form/4d554178/64413d3d",
            "user": "t",
        }
    ]


@pytest.mark.parametrize(
    "platform, version, expected",
    [
        ("x2", "0.0.0", True),
        ("xsoar", "8.4.0", True),
        ("xsoar_hosted", "6.0.0", False),
        ("xsoar", "6.12.0", False),
    ],
)
def test_is_machine_saas(mocker, platform, version, expected):
    """
    Given:
        - The platform and version args
    When:
        - `is_machine_saas` is called
    Then:
        - Ensure that returns as expected

    """
    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"platform": platform, "version": version},
    )
    assert is_machine_saas() == expected


@pytest.mark.parametrize(
    "is_saas, expected",
    [
        (True, "https://server/external/form/abc/xyz?otp=123"),
        (False, "https://server/#/external/form/abc/xyz"),
    ],
)
def test_generate_url(mocker, is_saas, expected):
    """
    Given:
        - server url, encoded task and user
    When:
        - `generate_url` is called
    Then:
        - it returns the expected url
    """
    mocker.patch("GetDataCollectionLink.is_machine_saas", return_value=is_saas)
    mocker.patch("GetDataCollectionLink.execute_command", return_value="123")

    url = generate_url("https://server", "abc", "xyz")

    assert url == expected


def test_generate_url_generateOTP_unsupported(mocker):
    """
    Given:
        - server url, encoded task and user
    When:
        - `generate_url` is called and `execute_command` raises `Unsupported Command` exception
    Then:
        - it returns the expected url without OTP
    """

    mocker.patch("GetDataCollectionLink.is_machine_saas", return_value=True)
    mocker.patch("GetDataCollectionLink.execute_command", side_effect=Exception("Unsupported Command"))

    url = generate_url("https://server", "abc", "xyz")

    assert url == "https://server/#/external/form/abc/xyz"


def test_generate_url_failure(mocker):
    """
    Given:
        - server url, encoded task and user
    When:
        - `generate_url` is called and `execute_command` raises an exception
    Then:
        - Ensure the exception is raised
    """

    mocker.patch("GetDataCollectionLink.is_machine_saas", return_value=True)
    mocker.patch("GetDataCollectionLink.execute_command", side_effect=Exception("test"))

    with pytest.raises(Exception):
        generate_url("https://server", "abc", "xyz")
