import json
from datetime import datetime, timedelta

import pytest
import requests_mock

MOCK_URL = "http://openphish.com"
MOCK_DELIVERED_MESSAGE = {}
from OpenPhish_v2 import Client, _is_reload_needed, remove_backslash, reload_command, status_command
from freezegun import freeze_time

import demistomock as demisto

RELOADED_DATA = [
    (Client(MOCK_URL, True, False, 2), {}, True),  # case no data in memory
    (Client(MOCK_URL, True, False, 2), {"list": []}, True),  # case no timestamp and list is emtpy
    (Client(MOCK_URL, True, False, 2),
     {"list": ['http://www.niccakorea.com/board/index.html',
               'http://lloyds.settlemypayee.uk',
               'https://whatsapp-chat02.zzux.com',
               'http://dd0ddddddcuser.ey.r.appspot.com'], "timestamp": None}, True),  # case no timestamp
    (Client(MOCK_URL, True, False, 1),
     {"list": ['http://www.niccakorea.com/board/index.html',
               'http://lloyds.settlemypayee.uk',
               'https://whatsapp-chat02.zzux.com',
               'http://dd0ddddddcuser.ey.r.appspot.com'],
      "timestamp": datetime(2020, 10, 1, 10, 00, 00, 0) - timedelta(hours=1)}, True),
    (Client(MOCK_URL, True, False, 2),
     {"list": ['http://www.niccakorea.com/board/index.html',
               'http://lloyds.settlemypayee.uk',
               'https://whatsapp-chat02.zzux.com',
               'http://dd0ddddddcuser.ey.r.appspot.com'],
      "timestamp": datetime(2020, 10, 1, 10, 00, 00, 0) - timedelta(hours=1)}, False),
    (Client(MOCK_URL, True, False, 0.5),
     {"list": ['http://www.niccakorea.com/board/index.html',
               'http://lloyds.settlemypayee.uk',
               'https://whatsapp-chat02.zzux.com',
               'http://dd0ddddddcuser.ey.r.appspot.com'],
      "timestamp": datetime(2020, 10, 1, 10, 00, 00, 0) - timedelta(hours=1)}, True)
]


@pytest.mark.parametrize('client,data,output', RELOADED_DATA)
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


LINKS = [
    ("goo.co/", "goo.co"),
    ("goo.co", "goo.co")]


@pytest.mark.parametrize('url, expected_result', LINKS)
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
    mock_data_from_api = 'https://cnannord.com/paypal/firebasecloud/83792/htmjrtfgdsaopjdnbhhdmmdgrhehnndnmmmbvvbnmndmnbnnbbmnm/service/paypal\nhttp://payameghdir.ir/cxxc/Owa/\nhttps://fxsearchdesk.net/Client/tang/step4.html\nhttps://fxsearchdesk.net/Client/tang/step3.html\nhttps://fxsearchdesk.net/Client/tang/step2.html\nhttp://fxsearchdesk.net/Client/tang/step2.html\nhttp://fxsearchdesk.net/Client/tang/step3.html\nhttp://fxsearchdesk.net/Client/tang/step4.html\nhttps://fxsearchdesk.net/Client/tang\nhttp://fxsearchdesk.net/Client/tang/\nhttp://fxsearchdesk.net/Client/tang\nhttp://revisepayee.com/admin\nhttp://hmrc.resolutionfix.com/\nhttps://hmrc.resolutionfix.com/refund/details'
    mocker.patch.object(Client, 'http_request', return_value=mock_data_from_api)
    mocker.patch.object(demisto, "setIntegrationContext")
    client = Client(
        url=MOCK_URL,
        use_ssl=False,
        use_proxy=False,
        fetch_interval_hours=1)
    status = reload_command(client)
    assert status.readable_output == "updated successfully"


STANDARD_NOT_LOADED_MSG = 'OpenPhish Database Status\nDatabase not loaded.\n'
STANDARD_4_LOADED_MSG = "OpenPhish Database Status\n" \
                        "Total **4** URLs loaded.\n" \
                        "Last load time **Thu Oct 01 2020 06:00:00**\n"
CONTEXT_MOCK_WITH_STATUS = [
    ({}, STANDARD_NOT_LOADED_MSG),  # case no data in memory
    ({"list": [], "timestamp": "1601532000000"},
     STANDARD_NOT_LOADED_MSG),  # case no timestamp and list is emtpy
    (
        {"list": ['http://www.niccakorea.com/board/index.html',
                  'http://lloyds.settlemypayee.uk',
                  'https://whatsapp-chat02.zzux.com',
                  'http://dd0ddddddcuser.ey.r.appspot.com'],
         "timestamp": "1601532000000"},  # datetime(2020, 10, 1, 10, 00, 00, 0) - timedelta(hours=1)}
        STANDARD_4_LOADED_MSG)
]


@pytest.mark.parametrize('data,expected_result', CONTEXT_MOCK_WITH_STATUS)
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
