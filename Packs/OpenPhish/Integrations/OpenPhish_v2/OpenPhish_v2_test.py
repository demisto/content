from datetime import datetime
import pytest
import OpenPhish_v2
import demistomock as demisto
from OpenPhish_v2 import (
    Client,
    _is_reload_needed,
    remove_backslash,
    reload_command,
    status_command,
    url_command,
)
from freezegun import freeze_time
from test_data.api_raw import RAW_DATA

MOCK_URL = "http://openphish.com"
MOCK_DELIVERED_MESSAGE = {}
DBOT_KEY = "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)"

RELOADED_DATA = [
    (Client(MOCK_URL, True, False, 2), {}, True),  # case no data in memory
    (
        Client(MOCK_URL, True, False, 2),
        {"list": []},
        True,
    ),  # case no timestamp and list is emtpy
    (
        Client(MOCK_URL, True, False, 2),
        {
            "list": [
                "hxxp://www.niccakorea.com/board/index.html",
                "hxxp://lloyds.settlemypayee.uk",
                "hxxp://whatsapp-chat02.zzux.com",
                "hxxp://dd0ddddddcuser.ey.r.appspot.com",
            ],
            "timestamp": None,
        },
        True,
    ),  # case no timestamp
    (
        Client(MOCK_URL, True, False, 1),
        {
            "list": [
                "hxxp://www.niccakorea.com/board/index.html",
                "hxxp://lloyds.settlemypayee.uk",
                "hxxp://whatsapp-chat02.zzux.com",
                "hxxp://dd0ddddddcuser.ey.r.appspot.com",
            ],
            "timestamp": 1601542800000,
        },  # datetime(2020, 10, 1, 10, 00, 00, 0) - timedelta(hours=1)
        True,
    ),
    (
        Client(MOCK_URL, True, False, 2),
        {
            "list": [
                "hxxp://www.niccakorea.com/board/index.html",
                "hxxp://lloyds.settlemypayee.uk",
                "hxxp://whatsapp-chat02.zzux.com",
                "hxxp://dd0ddddddcuser.ey.r.appspot.com",
            ],
            "timestamp": 1601542800000,
        },  # datetime(2020, 10, 1, 10, 00, 00, 0) - timedelta(hours=1)
        False,
    ),
    (
        Client(MOCK_URL, True, False, 0.5),
        {
            "list": [
                "hxxp://www.niccakorea.com/board/index.html",
                "hxxp://lloyds.settlemypayee.uk",
                "hxxp://whatsapp-chat02.zzux.com",
                "hxxp://dd0ddddddcuser.ey.r.appspot.com",
            ],
            "timestamp": 1601542800000,
        },  # datetime(2020, 10, 1, 10, 00, 00, 0) - timedelta(hours=1)
        True,
    ),
]


@pytest.mark.parametrize("client,data,output", RELOADED_DATA)
def test_is_reload_needed(mocker, client, data, output):
    """
    Given:
        - data as IntegrationContext

    When:
        - reload command was required

    Then:
        - Returns False if last reload occurred in the past fetch_interval_hours. True otherwise

    """
    with freeze_time(datetime(2020, 10, 1, 10, 00, 00, 0)):
        assert _is_reload_needed(client, data) == output


LINKS = [("goo.co/", "goo.co"), ("goo.co", "goo.co")]


@pytest.mark.parametrize("url, expected_result", LINKS)
def test_remove_backslash(url: str, expected_result: str):
    """
       Given:
           - string representing url

       When:
           - saving data from to the integration context or checking a specific url

       Then:
           - checks the url format is without a backslash as last character

       """
    assert remove_backslash(url) == expected_result


def test_reload_command(mocker):
    """
           When:
               - reloading data from to the api to integration context

           Then:
               - checks if the reloading finished successfully

           """
    mock_data_from_api = RAW_DATA
    mocker.patch.object(Client, "http_request", return_value=mock_data_from_api)
    mocker.patch.object(demisto, "setIntegrationContext")
    client = Client(
        url=MOCK_URL, use_ssl=False, use_proxy=False, fetch_interval_hours=1
    )
    status = reload_command(client)
    assert (
        status.readable_output
        == "Database was updated successfully to the integration context."
    )


STANDARD_NOT_LOADED_MSG = "OpenPhish Database Status\nDatabase not loaded.\n"
STANDARD_4_LOADED_MSG = (
    "OpenPhish Database Status\n"
    "Total **4** URLs loaded.\n"
    "Last load time **Thu Oct 01 2020 06:00:00 (UTC)**\n"
)
CONTEXT_MOCK_WITH_STATUS = [
    ({}, STANDARD_NOT_LOADED_MSG),  # case no data in memory
    (
        {"list": [], "timestamp": "1601532000000"},
        STANDARD_NOT_LOADED_MSG,
    ),  # case no timestamp and list is emtpy
    (
        {
            "list": [
                "hxxp://www.niccakorea.com/board/index.html",
                "hxxp://lloyds.settlemypayee.uk",
                "hxxp://whatsapp-chat02.zzux.com",
                "hxxp://dd0ddddddcuser.ey.r.appspot.com",
            ],
            "timestamp": "1601532000000",
        },  # datetime(2020, 10, 1, 10, 00, 00, 0) - timedelta(hours=1)}
        STANDARD_4_LOADED_MSG,
    ),
]


@pytest.mark.parametrize("data,expected_result", CONTEXT_MOCK_WITH_STATUS)
@freeze_time("1993-06-17 11:00:00 GMT")
def test_status_command(mocker, data, expected_result):
    """
    Given:
        - Integration context
    When:
        - After status command
    Then:
        - Returns number of loaded urls if data was loaded.
        - Otherwise, returns Database not loaded.
    """
    client = Client(MOCK_URL, True, False, 1)
    mocker.patch.object(demisto, "getIntegrationContext", return_value=data)
    status = status_command(client)
    assert status.readable_output == expected_result


CONTEXT_MOCK_WITH_URL = [
    (
        {"url": "hxxp://lloyds.settlemypayee.uk"},
        {
            "list": [
                "hxxp://www.niccakorea.com/board/index.html",
                "hxxp://lloyds.settlemypayee.uk",
                "hxxp://whatsapp-chat02.zzux.com",
                "hxxp://dd0ddddddcuser.ey.r.appspot.com",
            ],
            "timestamp": "1601532000000",
        },
        [
            {
                "URL": [
                    {
                        "Data": "hxxp://lloyds.settlemypayee.uk",
                        "Malicious": {
                            "Vendor": "OpenPhish",
                            "Description": "Match found in OpenPhish database",
                        },
                    }
                ],
                "DBOTSCORE": [
                    {
                        "Indicator": "hxxp://lloyds.settlemypayee.uk",
                        "Type": "url",
                        "Vendor": "OpenPhish",
                        "Score": 3,
                    }
                ],
            }
        ],
    ),
    (
        {"url": "hxxp://goo.co"},
        {
            "list": [
                "hxxp://www.niccakorea.com/board/index.html",
                "hxxp://lloyds.settlemypayee.uk",
                "hxxp://whatsapp-chat02.zzux.com",
                "hxxp://dd0ddddddcuser.ey.r.appspot.com",
            ],
            "timestamp": "1601532000000",
        },
        [
            {
                "URL": [{"Data": "hxxp://goo.co"}],
                "DBOTSCORE": [
                    {
                        "Indicator": "hxxp://goo.co",
                        "Type": "url",
                        "Vendor": "OpenPhish",
                        "Score": 0,
                    }
                ],
            }
        ],
    ),
    (
        {"url": "hxxp://whatsapp-chat02.zzux.com,hxxp://lloyds.settlemypayee.uk"},
        {
            "list": [
                "hxxp://www.niccakorea.com/board/index.html",
                "hxxp://lloyds.settlemypayee.uk",
                "hxxp://whatsapp-chat02.zzux.com",
                "hxxp://dd0ddddddcuser.ey.r.appspot.com",
            ],
            "timestamp": "1601532000000",
        },
        [
            {
                "URL": [
                    {
                        "Data": "hxxp://whatsapp-chat02.zzux.com",
                        "Malicious": {
                            "Vendor": "OpenPhish",
                            "Description": "Match found in OpenPhish database",
                        },
                    }
                ],
                "DBOTSCORE": [
                    {
                        "Indicator": "hxxp://whatsapp-chat02.zzux.com",
                        "Score": 3,
                        "Type": "url",
                        "Vendor": "OpenPhish",
                    }
                ],
            },
            {
                "URL": [
                    {
                        "Data": "hxxp://lloyds.settlemypayee.uk",
                        "Malicious": {
                            "Vendor": "OpenPhish",
                            "Description": "Match found in OpenPhish database",
                        },
                    }
                ],
                "DBOTSCORE": [
                    {
                        "Indicator": "hxxp://lloyds.settlemypayee.uk",
                        "Score": 3,
                        "Type": "url",
                        "Vendor": "OpenPhish",
                    }
                ],
            },
        ],
    ),
]


@pytest.mark.parametrize("url,context,expected_results", CONTEXT_MOCK_WITH_URL)
def test_url_command(mocker, url, context, expected_results):
    """
    Given:
        - a url

    When:
        - mocking the integration context data, runnig url_command

    Then:
        - validating whether the url is malicious (in integration context)

    """
    mocker.patch.object(
        demisto, "getIntegrationContext", return_value=context,
    )
    mocker.patch.object(OpenPhish_v2, "_is_reload_needed", return_value=False)
    client = Client(MOCK_URL, True, False, 1)
    results = url_command(client, **url)
    assert len(results) >= 1
    for i in range(len(results)):
        output = results[i].to_context().get("EntryContext", {})
        assert output.get(
            "URL(val.Data && val.Data == obj.Data)", []
        ) == expected_results[i].get("URL")
        assert output.get(DBOT_KEY, []) == expected_results[i].get("DBOTSCORE")
