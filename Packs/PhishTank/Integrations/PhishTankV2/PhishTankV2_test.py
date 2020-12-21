from datetime import datetime
import pytest
import demistomock as demisto
from freezegun import freeze_time
from PhishTankV2 import is_number, Client
from PhishTankV2 import remove_last_slash, is_reload_needed, reload
from PhishTankV2 import phishtank_status_command, url_command


def create_client(proxy: bool = False, verify: bool = False, fetch_interval_hours: str = "1"):
    return Client(proxy=proxy, verify=verify, fetch_interval_hours=fetch_interval_hours)


@pytest.mark.parametrize('number, output', [("True", False), ('432', True), ("str", False),
                                            ("455.55", True), ("-1", False),
                                            ("0", False), ("fd.f", False), ("1", True), ("", False)])
def test_is_number(number, output):
    """
    Given:
        - fetchIntervalHours as integration param

    When:
        - At the beginning of the integration

    Then:
        - Returns True if fetchIntervalHours is a positive number (float)
    """
    assert is_number(number) == output


@pytest.mark.parametrize('url, output',
                         [(r"hxxp://www.com/", r"hxxp://www.com"), (r"hxxp://www.com", r"hxxp://www.com"),
                          ("", "")])
def test_remove_last_slash(url, output):
    """
    Given:
        - Given url from an API response file or from integration args

    When:
        - Before operation with given url

    Then:
        - Return url without '/' in the end (if not exists return the given url)
    """
    assert remove_last_slash(url) == output


@pytest.mark.parametrize('client,data,output', [
    (Client(False, False, "2"), {}, True),
    (Client(False, False, "1"),
     {"list": {"id": 200}, "timestamp": 1601542800000}, False),
    (Client(False, False, "2"),
     {"list": {"id": 200}, "timestamp": 1601542800000}, False),
    (Client(False, False, "0.5"),
     {"list": {"id": 200}, "timestamp": 1601542800000}, True),
])
def test_is_reloaded_needed(client, data, output):
    """
    Given:
        - data as IntegrationContext

    When:
        - reload command was required

    Then:
        - Returns False if last reload occurred in the past fetch_interval_hours. True otherwise

    """
    with freeze_time(datetime(2020, 10, 1, 10, 00, 00, 0)):
        assert is_reload_needed(client, data) == output


FETCH_INDICATORS_PACKAGE = [
    (
        'http://url.example',
        200,
        "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
        "1,http://url.example1,http://url.example1,2019-10-20T23:54:13+00:00,yes,2019-10-20T23:54:13+00:00,yes,Other\n"
        "2,http://url.example2,http://url.example2,2019-10-20T23:54:14+00:00,yes,2019-10-20T23:54:14+00:00,yes,Target"
        "\n",
        {'http://url.example1': {"phish_id": "1", "submission_time": "2019-10-20T23:54:13+00:00",
                                 "verified": "yes", "verification_time": "2019-10-20T23:54:13+00:00",
                                 "online": "yes", "target": "Other"},
         'http://url.example2': {"phish_id": "2", "submission_time": "2019-10-20T23:54:14+00:00",
                                 "verified": "yes", "verification_time": "2019-10-20T23:54:14+00:00",
                                 "online": "yes", "target": "Target"}
         }
    ),
    (
        'http://url.example/',
        200,
        "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
        "1,http://url.example1,2019-10-20T23:54:13+00:00,yes,2019-10-20T23:54:13+00:00,yes,Other\n"
        "2,http://url.example2,"
        "http://url.example2,2019-10-20T23:54:14+00:00,yes,2019-10-20T23:54:14+00:00,yes,Target\n",
        {'http://url.example2': {"phish_id": "2", "submission_time": "2019-10-20T23:54:14+00:00",
                                 "verified": "yes", "verification_time": "2019-10-20T23:54:14+00:00",
                                 "online": "yes", "target": "Target"}
         }
    ),
    (
        'http://url.example/',
        509,
        "['You have exceeded the request rate limit for this method. Please see the response headers for usage stats."
        " For more information about rate limiting on Phishtank, please see our developer site: "
        "http://www.phishtank.com/developer_info.php']",
        {}
    ),
]


@pytest.mark.parametrize('url, status_code, data, expected_result', FETCH_INDICATORS_PACKAGE)
def test_reload(mocker, url, status_code, data, expected_result):
    """
    Given:
        - url:
            - on reload command : url is the end point to get all data
            - on url command : given url has to be checked

    When:
        - After reload or url command

    Then:
        - Returns the processed dictionary
    """
    mocker.patch.object(Client, "get_http_request", return_value=data)
    client = create_client(False, False, "1")
    if status_code == 200 or status_code == 509:
        got_data = reload(client)
        assert got_data == expected_result
    else:
        assert False


CONTEXT_LIST = [
    (
        {
        }, "PhishTankV2 Database Status\nDatabase not loaded.\n"
    ),
    (
        {}, "PhishTankV2 Database Status\nDatabase not loaded.\n"
    ),
    (
        {
            'list': {'http://url.example1': {"phish_id": "1", "submission_time": "2019-10-20T23:54:13+00:00",
                                             "verified": "yes", "verification_time": "2019-10-20T23:54:13+00:00",
                                             "online": "yes", "target": "Other"},
                     'http://url.example2': {"phish_id": "2", "submission_time": "2019-10-20T23:54:14+00:00",
                                             "verified": "yes", "verification_time": "2019-10-20T23:54:14+00:00",
                                             "online": "yes", "target": "Target"}
                     },
            'timestamp': 1601969897 * 1000
        }, "PhishTankV2 Database Status\nTotal **2** URLs loaded.\nLast Load time **Tue Oct 06 2020 07:38:17 (UTC)**\n"
    )
]


@pytest.mark.parametrize('data,expected_result', CONTEXT_LIST)
@freeze_time("1993-06-17 11:00:00 GMT")
def test_phishtank_status_command(mocker, data, expected_result):
    """
    Given:
        - Integration context

    When:
        - After asked fot status command

    Then:
        - Returns number of loaded urls if data was loaded.
        - Otherwise, returns Database not loaded.
    """
    mocker.patch.object(demisto, "getIntegrationContext", return_value=data)
    status = phishtank_status_command()
    assert status.readable_output == expected_result


URL_COMMAND_LIST = [
    (  # valid data , verified = yes
        {"phish_id": "1", "submission_time": "2019-10-20T23:54:13+00:00",
         "verified": "yes", "verification_time": "2019-10-20T23:54:13+00:00",
         "online": "yes", "target": "Other"
         }, ['http://url.example1'], 3,
        "### PhishTankV2 Database - URL Query \n#### Found matches for URL http://url.example1 \n|online"
        "|phish_id|submission_time|target|verification_time|verified|\n|---|---|---|---|---|---|\n| yes | 1 | "
        "2019-10-20T23:54:13+00:00 | Other | 2019-10-20T23:54:13+00:00 | yes |\nAdditional details at "
        "http://www.phishtank.com/phish_detail.php?phish_id=1 \n"
    ),
    (  # no exists key verified
        {"phish_id": "1", "submission_time": "2019-10-20T23:54:13+00:00",
         "verification_time": "2019-10-20T23:54:13+00:00",
         "online": "yes", "target": "Other"
         }, ['http://url.example1'], 0,
        "### PhishTankV2 Database - URL Query \n#### No matches for URL http://url.example1 \n"
    ),
    (  # valid data , verified = no
        {"phish_id": "1", "submission_time": "2019-10-20T23:54:13+00:00",
         "verified": "no", "verification_time": "2019-10-20T23:54:13+00:00",
         "online": "yes", "target": "Other"
         }, ['http://url.example1'],
        2,
        "### PhishTankV2 Database - URL Query \n#### Found matches for URL http://url.example1 \n|online"
        "|phish_id|submission_time|target|verification_time|verified|\n|---|---|---|---|---|---|\n| yes | 1 | "
        "2019-10-20T23:54:13+00:00 | Other | 2019-10-20T23:54:13+00:00 | no |\nAdditional details at "
        "http://www.phishtank.com/phish_detail.php?phish_id=1 \n"
    ),
    (  # no data
        {}, ['http://url.example1'],
        0,
        "### PhishTankV2 Database - URL Query \n#### No matches for URL http://url.example1 \n"
    ),
]


@pytest.mark.parametrize('data,url,expected_score,expected_table', URL_COMMAND_LIST)
def test_url_command(mocker, data, url, expected_score, expected_table):
    """
    Given:
        - Got url to check for scores

    When:
        - After asked fot url command

    Then:
        - validating that the IOC score is as expected
        - validating the returned human readable
    """
    client = create_client(False, False, "1")
    mocker.patch.object(demisto, "results")
    mocker.patch('PhishTankV2.get_url_data', return_value=(data, url[0]))
    command_results = url_command(client, url)

    # validate score
    output = command_results[0].to_context().get('EntryContext', {})
    dbot_key = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&' \
               ' val.Vendor == obj.Vendor && val.Type == obj.Type)'
    assert output.get(dbot_key, [])[0].get('Score') == expected_score

    # validate human readable
    hr_ = command_results[0].to_context().get('HumanReadable', {})
    assert hr_ == expected_table
