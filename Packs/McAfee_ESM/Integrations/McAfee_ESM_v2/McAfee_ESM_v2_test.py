import datetime

import pytest
from freezegun import freeze_time
from McAfee_ESM_v2 import *
from McAfee_ESM_v2 import McAfeeESMClient

list_test_filtering_incidents = [{"id": 3}, {"id": 1}, {"id": 5}, {"id": 4}, {"id": 0}, {"id": 2}]
data_test_filtering_incidents = [
    ((0, 0), ([5, 4, 3, 2, 1])),
    ((0, 1), ([1])),
    ((0, 2), ([2, 1])),
    ((3, 1), ([4])),
    ((3, 0), ([5, 4])),
]
data_test_expected_errors = [
    ("error", False),
    ("", False),
    ("alarmUnacknowledgeTriggeredAlarm failed with error[ERROR_BadRequest (60)].", True),
    ("alarmAcknowledgeTriggeredAlarm failed with error[ERROR_BadRequest (60)].", True),
    (
        "qryGetResults failed with error[Error deserializing EsmQueryResults, see logs for more information "
        "(Error deserializing EsmQueryResults, see logs for more information "
        "(Internal communication error, see logs for more details))].",
        True,
    ),
]
data_test_time_format = [
    ("", "time data '' does not match the time format."),
    ("test", "time data 'test' does not match the time format."),
]
data_test_convert_time_format = [
    (("2019-12-19T00:00:00", 0, False), "2019-12-19T00:00:00Z"),
    (("2019-12-19T00:00:00", 2, False), "2019-12-19T02:00:00Z"),
    (("2019-12-19T02:00:00", -2, False), "2019-12-19T00:00:00Z"),
    (("2019-12-19T00:00:00Z", 0, False), "2019-12-19T00:00:00Z"),
    (("2019-12-19T00:00:00Z", 2, False), "2019-12-19T02:00:00Z"),
    (("2019-12-19T02:00:00Z", -2, False), "2019-12-19T00:00:00Z"),
    (("2019/12/19 00:00:00", 0, True), "2019-12-19T00:00:00Z"),
    (("2019/12/19 00:00:00", -2, True), "2019-12-19T02:00:00Z"),
    (("2019/12/19 02:00:00", 2, True), "2019-12-19T00:00:00Z"),
]
data_test_set_query_times = [
    ((None, None, None, 0), ("CUSTOM", None, None)),
    (("1 day", None, None, 0), ("1 day", "2019/12/31 00:00:00", None)),
    (("LAST_WEEK", "", None, 0), ("LAST_WEEK", "", None)),
    (("LAST_YEAR", "TEST", None, 0), "Invalid set times."),
    (("LAST_YEAR", None, "TEST", 0), "Invalid set times."),
    ((None, "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z", 0), ("CUSTOM", "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")),
]
data_test_list_times_set = [
    (([], [], 0), []),
    (([0, 0], [], 2), [0, 0]),
    (
        (["2019/12/19 00:00:00", "2019/12/19 00:00:00", 0, "2019/12/19 00:00:00"], [0, 1], 0),
        ["2019-12-19T00:00:00Z", "2019-12-19T00:00:00Z", 0, "2019/12/19 00:00:00"],
    ),
    (([0, "2019/12/19 00:00:00"], [1], -2), [0, "2019-12-19T02:00:00Z"]),
    (([0, "2019/12/19 00:00:00"], [], -2), [0, "2019/12/19 00:00:00"]),
    ((["2019/12/19 00:00:00"], [0], -2), ["2019-12-19T02:00:00Z"]),
]
data_test_time_fields = [
    [["time", "date"], [0, 1]],
    [["name", "TiMe", "Datetime"], [1, 2]],
    [[], []],
    [["r", "t"], []],
    [["", ""], []],
]
data_test_mcafee_severity_to_demisto = [(100, 3), (65, 2), (32, 1), (0, 0)]


@pytest.mark.parametrize("test_input, output", data_test_filtering_incidents)
def test_filtering_incidents(test_input, output):
    temp_output = filtering_incidents(list_test_filtering_incidents, test_input[0], test_input[1])
    test_output = [0] * len(temp_output)
    for i in range(len(temp_output)):
        test_output[i] = temp_output[i]["id"]
    assert test_output == output, f"filtering_incidents({test_input}) returns: {test_input} instead: {output}."


@pytest.mark.parametrize("test_input, output", data_test_expected_errors)
def test_expected_errors(test_input, output):
    assert expected_errors(test_input) == output, f"expected_errors({test_input}) returns: {not output} instead: {output}."


@pytest.mark.parametrize("test_input, output", data_test_time_format)
def test_time_format(test_input, output):
    test_output = None
    try:
        test_output = time_format(test_input)
    except ValueError as error:
        test_output = str(error)
    finally:
        assert test_output == output, f"time_format({test_input}) returns error: {test_output} instead: {output}."


@pytest.mark.parametrize("test_input, output", data_test_convert_time_format)
def test_convert_time_format(test_input, output):
    temp = convert_time_format(test_input[0], test_input[1], test_input[2])
    assert (
        temp == output
    ), f"convert_time_format({test_input[0]}, {test_input[1]}, {test_input[2]}) returns: {temp} instead: {output}."


@freeze_time("2020-01-01 00:00:00")
@pytest.mark.parametrize("test_input, output", data_test_set_query_times)
def test_set_query_times(test_input, output):
    test_output = None
    try:
        test_output = set_query_times(test_input[0], test_input[1], test_input[2], test_input[3])
    except ValueError as error:
        test_output = str(error)
    finally:
        assert test_output == output, f"time_format({test_input}) returns: {test_output} instead: {output}."


@pytest.mark.parametrize("test_input, output", data_test_list_times_set)
def test_list_times_set(test_input, output):
    temp = list_times_set(test_input[0], test_input[1], test_input[2])
    assert temp == output, f"list_times_set({test_input[0]}, {test_input[1]}, {test_input[2]}) returns: {temp} instead: {output}."


@pytest.mark.parametrize("test_input, output", data_test_time_fields)
def test_time_fields(test_input, output):
    for i in range(len(test_input)):
        test_input[i] = {"name": test_input[i]}
    temp = time_fields(test_input)
    assert temp == output, f"time_fields({test_input}) returns: {temp} instead: {output}."


@pytest.mark.parametrize("test_input, output", data_test_mcafee_severity_to_demisto)
def test_mcafee_severity_to_demisto(test_input, output):
    temp = mcafee_severity_to_demisto(test_input)
    assert temp == output, f"mcafee_severity_to_demisto({test_input}) returns: {temp} instead: {output}."


@pytest.mark.filterwarnings(
    "ignore::urllib3.exceptions.InsecureRequestWarning", "ignore::pytest.PytestUnraisableExceptionWarning"
)
def test_edit_case(mocker):
    params = {
        "url": "https://example.com",
        "insecure": True,
        "credentials": {"identifier": "TEST", "password": "TEST"},
        "version": "11.6.11",
    }
    raw_response_has_event_list = {
        "assignedTo": 8207,
        "closeTime": "2021-05-25T10:29:17Z",
        "dataSourceList": ["47"],
        "deviceList": None,
        "eventList": [{"id": "144117387300438016|6204912068", "lastTime": "2021-05-25T09:47:10Z", "message": "TEST"}],
        "history": "\n------- Viewed: 05/25/2021 10:26:37(GMT)"
        "TEST@TEST -------\n\n------- Viewed: 05/25/2021 10:27:34("
        "GMT) "
        "   TEST@TEST -------\n",
        "id": 58136,
        "notes": "------- Opened on 2021/05/25 09:53:53(GMT) by Triggered Condition -------"
        "\n\n------- In Progress: 05/25/2021 10:29:17(GMT)   Xsoar@TEST -------"
        "\n\n------- Changes:  05/25/2021 10:29:17(GMT)   Xsoar@TEST -------"
        "\n  Organization\n    old: None\n    new: BRD"
        "\n\n",
        "openTime": "2021-05-25T09:53:53Z",
        "orgId": 2,
        "severity": 50,
        "statusId": 3,
        "summary": "ALERT - Scan",
    }

    mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__set_session", return_value={})
    mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__request", return_value={})
    mocker.patch.object(McAfeeESMClient, "get_case_detail", return_value=("", {}, raw_response_has_event_list))
    try:
        client = McAfeeESMClient(params)
        client.edit_case()
        result = client._McAfeeESMClient__request.call_args.kwargs["data"]["caseDetail"]
    except Exception:
        pass
    assert len(result["eventList"]) > 0


MOCK_CURRENT_TIME = "2022-10-18T16:46:25Z"


def create_time_difference_string(days=0, hours=0):
    datetime_freezed = datetime.strptime(MOCK_CURRENT_TIME, McAfeeESMClient.demisto_format)
    return datetime.strftime(datetime_freezed - timedelta(days=days, hours=hours), McAfeeESMClient.demisto_format)


FETCH_PARAMS = {
    "url": "https://example.com",
    "insecure": True,
    "credentials": {"identifier": "TEST", "password": "TEST"},
    "version": "11.6.11",
    "fetchTime": "3 days",
    "startingFetchID": 0,
    "fetchLimitAlarms": 50,
}


def run_fetch(mocker, last_run: dict, raw_alarms, params: dict | None = None):
    """Runs fetch-incidents with the given lastRun and raw ESM alarms response, and returns the fetch_alarms spy,
    the incidents and the new lastRun."""
    mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__set_session", return_value={})
    mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__request", return_value=raw_alarms)
    mocker.patch.object(demisto, "args", return_value={})
    fetch_alarms_mock = mocker.spy(McAfeeESMClient, "fetch_alarms")
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")
    client = McAfeeESMClient(params or FETCH_PARAMS)
    client.fetch_incidents(params=params or FETCH_PARAMS)
    return fetch_alarms_mock, demisto.incidents.call_args[0][0], demisto.setLastRun.call_args[0][0]["alarms"]


@freeze_time(MOCK_CURRENT_TIME)
def test_fetch_alarms_empty_response_moves_window_forward(mocker):
    """
    Given:
    - A lastRun from the current fetch logic, 3 days in the past.
    When:
    - ESM returns an empty response ({}) for the fetch window.
    Then:
    - The query window is bounded to the maximum fetch window (1 hour).
    - The next start time moves forward to the window end minus the lookback, instead of staying the same.
    """
    last_run = {"alarms": {"id": 10, "time": create_time_difference_string(days=3), "version": 2}}
    fetch_alarms_mock, incidents, new_last_run = run_fetch(mocker, last_run, raw_alarms={})

    assert fetch_alarms_mock.call_args.kwargs["start_time"] == create_time_difference_string(days=3)
    assert fetch_alarms_mock.call_args.kwargs["end_time"] == create_time_difference_string(days=3, hours=-1)
    assert incidents == []
    assert new_last_run == {"id": 10, "time": "2022-10-15T17:36:25Z", "version": 2}


@freeze_time(MOCK_CURRENT_TIME)
def test_fetch_alarms_window_ends_at_now(mocker):
    """
    Given:
    - A lastRun 5 minutes in the past.
    When:
    - Fetching, and ESM returns no alarms.
    Then:
    - The window ends at the current time, and the next start time does not move backwards.
    """
    start_time = "2022-10-18T16:41:25Z"
    last_run = {"alarms": {"id": 10, "time": start_time, "version": 2}}
    fetch_alarms_mock, _, new_last_run = run_fetch(mocker, last_run, raw_alarms=[])

    assert fetch_alarms_mock.call_args.kwargs["end_time"] == MOCK_CURRENT_TIME
    assert new_last_run["time"] == start_time


@freeze_time(MOCK_CURRENT_TIME)
def test_fetch_alarms_all_new_alarms_returned(mocker):
    """
    Given:
    - A lastRun 30 minutes in the past with ID 10.
    When:
    - ESM returns an old alarm (ID 10) and two new alarms, within the fetch limit.
    Then:
    - Two incidents are returned, the last run ID is the newest alarm ID, and the window moves forward.
    """
    last_run = {"alarms": {"id": 10, "time": "2022-10-18T16:16:25Z", "version": 2}}
    raw_alarms = [
        {"id": 10, "triggeredDate": "2022/10/18 16:17:00"},
        {"id": 11, "triggeredDate": "2022/10/18 16:20:00"},
        {"id": 12, "triggeredDate": "2022/10/18 16:30:00"},
    ]
    _, incidents, new_last_run = run_fetch(mocker, last_run, raw_alarms)

    assert len(incidents) == 2
    assert new_last_run == {"id": 12, "time": "2022-10-18T16:36:25Z", "version": 2}


@freeze_time(MOCK_CURRENT_TIME)
def test_fetch_alarms_limit_reached_continues_from_newest_alarm(mocker):
    """
    Given:
    - A fetch limit of 1.
    When:
    - ESM returns two new alarms.
    Then:
    - The alarm with the lower ID is returned, and the next start time is its triggered time.
    """
    params = FETCH_PARAMS | {"fetchLimitAlarms": 1}
    last_run = {"alarms": {"id": 10, "time": "2022-10-18T16:16:25Z", "version": 2}}
    raw_alarms = [
        {"id": 12, "triggeredDate": "2022/10/18 16:30:00"},
        {"id": 11, "triggeredDate": "2022/10/18 16:20:00"},
    ]
    _, incidents, new_last_run = run_fetch(mocker, last_run, raw_alarms, params)

    assert len(incidents) == 1
    assert new_last_run == {"id": 11, "time": "2022-10-18T16:20:00Z", "version": 2}


@freeze_time("2026-11-03T08:05:35Z")
def test_fetch_alarms_day_first_esm_does_not_get_stuck(mocker):
    """
    Given:
    - The lastRun from XSUP-80724: written by the previous fetch logic with a day/month swapped time
      (2026-03-11, which is November 3 on a day-first ESM).
    - The ESM date format parameter set to DD/MM/YYYY, and a fetch limit of 1.
    When:
    - Fetching, and ESM returns two new alarms with day-first dates.
    Then:
    - The fetch starts from the first fetch time instead of March 11.
    - The alarm dates are parsed as November 3, and the next start time is the returned alarm time.
    """
    params = FETCH_PARAMS | {"dateFormat": "DD/MM/YYYY", "fetchTime": "1 hour", "fetchLimitAlarms": 1}
    last_run = {"alarms": {"id": 760346, "time": "2026-03-11T07:59:37Z"}}
    raw_alarms = [
        {"id": 760348, "triggeredDate": "03/11/2026 07:30:00"},
        {"id": 760347, "triggeredDate": "03/11/2026 07:20:00"},
    ]
    fetch_alarms_mock, incidents, new_last_run = run_fetch(mocker, last_run, raw_alarms, params)

    assert fetch_alarms_mock.call_args.kwargs["start_time"] == "2026-11-03T07:05:35Z"
    assert len(incidents) == 1
    assert new_last_run == {"id": 760347, "time": "2026-11-03T07:20:00Z", "version": 2}


@freeze_time(MOCK_CURRENT_TIME)
@pytest.mark.parametrize(
    "alarms_last_run, expected",
    [
        pytest.param({}, "2022-10-15T16:46:25Z", id="no last run"),
        pytest.param({"id": 1, "time": "2022-10-17T00:00:00Z"}, "2022-10-17T00:00:00Z", id="legacy, after first fetch"),
        pytest.param({"id": 1, "time": "2022-03-10T00:00:00Z"}, "2022-10-15T16:46:25Z", id="legacy, before first fetch"),
        pytest.param({"id": 1, "time": "2022-03-10T00:00:00Z", "version": 2}, "2022-03-10T00:00:00Z", id="current, old"),
        pytest.param({"id": 1, "time": "2022-12-10T00:00:00Z", "version": 2}, "2022-10-15T16:46:25Z", id="in the future"),
        pytest.param({"id": 1, "time": "10/12/2022"}, "2022-10-15T16:46:25Z", id="invalid format"),
    ],
)
def test_get_alarms_fetch_start_time(alarms_last_run, expected):
    """
    Given:
    - An alarms lastRun object.
    When:
    - Calculating the start time of the fetch window, with a first fetch time of 3 days ago.
    Then:
    - Legacy times before the first fetch time, future times and invalid times fall back to the first fetch time.
    """
    assert get_alarms_fetch_start_time(alarms_last_run, "2022-10-15T16:46:25Z") == expected


def test_get_fetch_window_end_rejects_non_positive_window():
    """
    Given:
    - A maximum fetch window of 0 hours.
    When:
    - Calculating the fetch window end.
    Then:
    - An error is raised.
    """
    with pytest.raises(DemistoException, match="must be a positive number"):
        get_fetch_window_end("2022-10-18T16:00:00Z", datetime.utcnow(), 0)


def test_get_next_alarms_fetch_start_ignores_alarm_time_outside_window():
    """
    Given:
    - A fetch window that was not consumed, and a newest alarm time outside the window (a misparsed date).
    When:
    - Calculating the next start time.
    Then:
    - The start time stays on the current window.
    """
    assert (
        get_next_alarms_fetch_start("2026-11-03T07:00:00Z", "2026-11-03T08:00:00Z", "2026-03-11T07:30:00Z", False)
        == "2026-11-03T07:00:00Z"
    )


@pytest.mark.parametrize(
    "date_format, esm_time, expected",
    [
        pytest.param("Auto detect", "03/11/2026 08:21:18", "2026-03-11T08:21:18Z", id="auto, ambiguous is month first"),
        pytest.param("Auto detect", "13/11/2026 08:21:18", "2026-11-13T08:21:18Z", id="auto, day greater than 12"),
        pytest.param("Auto detect", "2026/11/03 08:21:18", "2026-11-03T08:21:18Z", id="auto, year first"),
        pytest.param("DD/MM/YYYY", "03/11/2026 08:21:18", "2026-11-03T08:21:18Z", id="day first"),
        pytest.param("MM/DD/YYYY", "11/03/2026 08:21:18", "2026-11-03T08:21:18Z", id="month first"),
        pytest.param("DD/MM/YYYY", "03-11-2026 08:21:18", "2026-11-03T08:21:18Z", id="dashes"),
    ],
)
def test_time_format_with_date_format(date_format, esm_time, expected):
    """
    Given:
    - The ESM date format parameter, and a date returned by ESM.
    When:
    - Converting the date to the demisto format.
    Then:
    - The date is parsed according to the date format.
    """
    set_esm_date_format(date_format)
    try:
        assert time_format(esm_time) == expected
    finally:
        set_esm_date_format("Auto detect")


def test_time_format_month_first_rejects_day_greater_than_12():
    """
    Given:
    - The ESM date format parameter set to MM/DD/YYYY.
    When:
    - Converting a date whose first part is greater than 12.
    Then:
    - An error is raised instead of guessing the format.
    """
    set_esm_date_format("MM/DD/YYYY")
    try:
        with pytest.raises(ValueError, match="does not match the time format"):
            time_format("13/11/2026 08:21:18")
    finally:
        set_esm_date_format("Auto detect")


def test_set_esm_date_format_rejects_invalid_value():
    """
    Given:
    - An invalid ESM date format value.
    When:
    - Setting the date format.
    Then:
    - An error is raised.
    """
    with pytest.raises(DemistoException, match="Invalid ESM date format"):
        set_esm_date_format("YYYY.MM.DD")


# testing if can upload
class TestTestModule:
    @staticmethod
    @pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
    def test_sanity(mocker):
        params = {
            "url": "https://example.com",
            "insecure": True,
            "credentials": {"identifier": "Shahaf", "password": "TEST"},
            "version": "11.6.11",
        }
        mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__set_session", return_value={})
        mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__request", return_value={})
        try:
            client = McAfeeESMClient(params)
            _, _, raw = client.test_module()
        except Exception:
            pass
        assert raw == "ok"

    @staticmethod
    def test_invalid_starting_id(mocker):
        params = {
            "url": "https://example.com",
            "insecure": True,
            "credentials": {
                "identifier": "Shahaf",
                "password": "TEST",
            },
            "version": "11.6.11",
            "startingFetchID": "",
            "isFetch": True,
        }
        mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__set_session", return_value={})
        mocker.patch.object(McAfeeESMClient, "_http_request")
        mocker.patch.object(demisto, "params", return_value=params)
        client = McAfeeESMClient(params)
        with pytest.raises(DemistoException):
            client.test_module()


# Test vectors published by Trellix in KB90289 (https://support.trellix.com/s/article/KB90289).
# The article's prose labels the second plaintext "Trellix123!", but its ciphertext actually
# decrypts to "Mcafee123!" - a stale value left over from the McAfee-to-Trellix rebrand.
# The plaintext below is the one that genuinely round-trips against the published ciphertext.
data_test_encrypt_credential = [
    ("NGCP", "jwNLgaSY2PFsAjF87bRyPg=="),
    ("Mcafee123!", "uTl8FIeRQJNFOybh6521Hg=="),
]


@pytest.mark.parametrize("plaintext, expected", data_test_encrypt_credential)
def test_encrypt_credential_matches_vendor_vectors(plaintext, expected):
    """
    Given:
    - A credential and the matching AES ciphertext published by Trellix in KB90289.

    When:
    - Encrypting the credential for an ESM 11.6.11+ login.

    Then:
    - The result matches the vendor's published ciphertext exactly, confirming the
      integration interoperates with the ESM login API (AES-128-CBC, PKCS7, base64).
    """
    assert encrypt_credential(plaintext) == expected


def test_encode_credential_aes_version():
    """
    Given:
    - An instance configured with ESM 11.6.11 (AES threshold).

    When:
    - Encoding a credential for the login request.

    Then:
    - The credential is AES-encrypted rather than only base64-encoded.
    """
    assert encode_credential("NGCP", "11.6.11") == "jwNLgaSY2PFsAjF87bRyPg=="


def test_encode_credential_base64_version():
    """
    Given:
    - An instance configured with ESM 11.6.10 (last Base64 version).

    When:
    - Encoding a credential for the login request.

    Then:
    - The legacy base64 encoding is used, unchanged from previous versions.
    """
    assert encode_credential("NGCP", "11.6.10") == base64.b64encode(b"NGCP").decode()


def test_encode_credential_non_ascii():
    """
    Given:
    - A password containing non-ASCII characters.

    When:
    - Encoding it for both the Base64 (11.6.0) and AES (11.6.11) paths.

    Then:
    - Encoding succeeds (UTF-8), and the AES result decrypts back to the original password.
    """
    password = "sécrèt-ñ-密碼"
    assert encode_credential(password, "11.6.0") == base64.b64encode(password.encode("utf-8")).decode()

    from cryptography.hazmat.primitives import padding as crypto_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    ciphertext = base64.b64decode(encode_credential(password, "11.6.11"))
    decryptor = Cipher(algorithms.AES(ESM_AES_KEY), modes.CBC(ESM_AES_IV)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = crypto_padding.PKCS7(AES_BLOCK_SIZE_BITS).unpadder()
    assert (unpadder.update(padded) + unpadder.finalize()).decode("utf-8") == password


@pytest.mark.parametrize("version", ["10.2", "11.1", "11.3", "11.5.9", "11.5"])
def test_validate_version_rejects_below_11_6(version):
    """
    Given:
    - An instance configured with an ESM version below 11.6.0 (Trellix end-of-life).

    When:
    - Validating the version.

    Then:
    - A DemistoException is raised immediately, naming the configured version and the
      minimum supported version, so the user can fix the instance.
    """
    with pytest.raises(DemistoException) as exception_info:
        validate_version(version)

    message = str(exception_info.value)
    assert version in message
    assert "11.6.0" in message


@pytest.mark.parametrize("version", ["", "latest", "11.6.11 and later", "v11,6,11", "eleven"])
def test_validate_version_rejects_invalid_version_string(version):
    """
    Given:
    - A *Version* parameter that is not a version number (for example a label or free text).

    When:
    - Validating the version.

    Then:
    - A DemistoException with an actionable message is raised instead of an unhandled
      packaging.version.InvalidVersion error.
    """
    with pytest.raises(DemistoException) as exception_info:
        validate_version(version)

    message = str(exception_info.value)
    assert "Invalid ESM version" in message
    assert "11.6.11" in message


@pytest.mark.parametrize(
    "version",
    ["11.6.0", "11.6.5", "11.6.10", "11.6.11", "11.6.20", "11.7.0", "12.0.0", "11.6", "11.7"],
)
def test_validate_version_accepts_supported(version):
    """
    Given:
    - An instance configured with a supported ESM version (11.6.0 or later), including
      short two-part versions like "11.6" and "11.7".

    When:
    - Validating the version.

    Then:
    - No exception is raised.
    """
    validate_version(version)


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_client_init_rejects_unsupported_version(mocker):
    """
    Given:
    - An existing instance that was configured before support for versions earlier than 11.6 was removed.

    When:
    - The client is initialized after the upgrade.

    Then:
    - Initialization fails fast with an actionable error, before any login attempt is made.
    """
    mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__set_session", return_value={})
    params = {
        "url": "https://example.com",
        "insecure": True,
        "credentials": {"identifier": "TEST", "password": "TEST"},
        "version": "11.3",
    }
    with pytest.raises(DemistoException, match="is not supported"):
        McAfeeESMClient(params)


@pytest.mark.filterwarnings(
    "ignore::urllib3.exceptions.InsecureRequestWarning", "ignore::pytest.PytestUnraisableExceptionWarning"
)
@pytest.mark.parametrize(
    "version, expected_username",
    [
        ("11.6.11", "jwNLgaSY2PFsAjF87bRyPg=="),
        ("11.6.10", base64.b64encode(b"NGCP").decode()),
    ],
)
def test_login_body_encoding_per_version(mocker, version, expected_username):
    """
    Given:
    - An instance configured with each of the supported ESM versions.

    When:
    - The client logs in.

    Then:
    - The login request body carries the credentials encoded as that version requires,
      and the session headers are taken from the response.
    """

    class MockResponse:
        status_code = 200
        text = ""
        headers = {"Xsrf-Token": "test-xsrf"}

        class cookies:  # noqa: N801
            @staticmethod
            def get(_name):
                return "test-jwt"

    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    http_request = mocker.patch.object(McAfeeESMClient, "_http_request", return_value=MockResponse())
    params = {
        "url": "https://example.com",
        "insecure": True,
        "credentials": {"identifier": "NGCP", "password": "NGCP"},
        "version": version,
    }

    client = McAfeeESMClient(params)

    login_body = json.loads(http_request.call_args.kwargs["data"])
    assert login_body["username"] == expected_username
    assert login_body["password"] == expected_username
    assert login_body["locale"] == "en_US"
    assert client._headers["Cookie"] == "JWTToken=test-jwt"
    assert client._headers["X-Xsrf-Token"] == "test-xsrf"


@pytest.mark.filterwarnings(
    "ignore::urllib3.exceptions.InsecureRequestWarning", "ignore::pytest.PytestUnraisableExceptionWarning"
)
def test_session_is_cached_in_integration_context(mocker):
    """
    Given:
    - An instance with no cached ESM session.

    When:
    - The client is initialized and logs in.

    Then:
    - The JWT and XSRF tokens are stored in the integration context with an expiry,
      so the next execution can reuse them instead of logging in again.
    """

    class MockResponse:
        status_code = 200
        text = ""
        headers = {"Xsrf-Token": "test-xsrf"}

        class cookies:  # noqa: N801
            @staticmethod
            def get(_name):
                return "test-jwt"

    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    set_context = mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(McAfeeESMClient, "_http_request", return_value=MockResponse())

    McAfeeESMClient(
        {
            "url": "https://example.com",
            "insecure": True,
            "credentials": {"identifier": "NGCP", "password": "NGCP"},
            "version": "11.6.11",
        }
    )

    cached_session = set_context.call_args[0][0][SESSION_CACHE_KEY]
    assert cached_session["cookie"] == "JWTToken=test-jwt"
    assert cached_session["xsrf_token"] == "test-xsrf"
    assert cached_session["expiry"] > time.time()


@pytest.mark.filterwarnings(
    "ignore::urllib3.exceptions.InsecureRequestWarning", "ignore::pytest.PytestUnraisableExceptionWarning"
)
def test_valid_cached_session_is_reused_without_login(mocker):
    """
    Given:
    - A cached ESM session in the integration context that has not expired.

    When:
    - The client is initialized.

    Then:
    - The cached tokens are used for the session headers and no login request is sent.
    """
    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            SESSION_CACHE_KEY: {
                "cookie": "JWTToken=cached-jwt",
                "xsrf_token": "cached-xsrf",
                "expiry": time.time() + SESSION_TTL_SECONDS,
            }
        },
    )
    http_request = mocker.patch.object(McAfeeESMClient, "_http_request")

    client = McAfeeESMClient(
        {
            "url": "https://example.com",
            "insecure": True,
            "credentials": {"identifier": "NGCP", "password": "NGCP"},
            "version": "11.6.11",
        }
    )

    assert client._headers["Cookie"] == "JWTToken=cached-jwt"
    assert client._headers["X-Xsrf-Token"] == "cached-xsrf"
    http_request.assert_not_called()


@pytest.mark.filterwarnings(
    "ignore::urllib3.exceptions.InsecureRequestWarning", "ignore::pytest.PytestUnraisableExceptionWarning"
)
def test_expired_cached_session_triggers_login(mocker):
    """
    Given:
    - A cached ESM session in the integration context whose expiry has passed.

    When:
    - The client is initialized.

    Then:
    - The stale session is discarded and a new login request is sent.
    """

    class MockResponse:
        status_code = 200
        text = ""
        headers = {"Xsrf-Token": "fresh-xsrf"}

        class cookies:  # noqa: N801
            @staticmethod
            def get(_name):
                return "fresh-jwt"

    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            SESSION_CACHE_KEY: {
                "cookie": "JWTToken=stale-jwt",
                "xsrf_token": "stale-xsrf",
                "expiry": time.time() - 1,
            }
        },
    )
    mocker.patch.object(demisto, "setIntegrationContext")
    http_request = mocker.patch.object(McAfeeESMClient, "_http_request", return_value=MockResponse())

    client = McAfeeESMClient(
        {
            "url": "https://example.com",
            "insecure": True,
            "credentials": {"identifier": "NGCP", "password": "NGCP"},
            "version": "11.6.11",
        }
    )

    assert http_request.call_args.args[1] == "login"
    assert client._headers["Cookie"] == "JWTToken=fresh-jwt"
    assert client._headers["X-Xsrf-Token"] == "fresh-xsrf"


class LoginResponse:
    """A successful ESM login response."""

    status_code = 200
    text = ""
    headers = {"Xsrf-Token": "fresh-xsrf"}

    class cookies:  # noqa: N801
        @staticmethod
        def get(_name):
            return "fresh-jwt"


class ApiResponse:
    """An ESM response to a command request."""

    def __init__(self, status_code: int, content: bytes):
        self.status_code = status_code
        self.content = content
        self.ok = status_code < 300

    def json(self):
        return json.loads(self.content)


def build_add_watchlist_client(mocker):
    """Builds a logged-in client and returns it with the patched _http_request for the next call."""
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(McAfeeESMClient, "_http_request", return_value=LoginResponse())
    client = McAfeeESMClient(
        {
            "url": "https://example.com",
            "insecure": True,
            "credentials": {"identifier": "NGCP", "password": "NGCP"},
            "version": "11.6.11",
        }
    )
    http_request = mocker.patch.object(McAfeeESMClient, "_http_request", return_value=ApiResponse(200, b'{"value": 54}'))
    return client, http_request


@pytest.mark.filterwarnings(
    "ignore::urllib3.exceptions.InsecureRequestWarning", "ignore::pytest.PytestUnraisableExceptionWarning"
)
def test_add_watchlist_sends_values(mocker):
    """
    Given:
    - A request to create a watchlist.

    When:
    - The create-watchlist request body is built.

    Then:
    - "values" is sent. ESM 11.7.1 rejects a body without it, with the opaque
      "Error processing request, see server logs for more details (null)". Verified on the
      appliance: adding "values" as the only change to the failing body creates the watchlist.
    """
    client, http_request = build_add_watchlist_client(mocker)
    client.args = {"name": "test_watchlist", "type": "IPAddress"}
    client.add_watchlist()

    assert json.loads(http_request.call_args.kwargs["data"]) == {
        "watchlist": {
            "name": "test_watchlist",
            "type": {"name": "IPAddress", "id": 0},
            "customType": {"name": "IPAddress", "id": 0},
            "dynamic": False,
            "enabled": True,
            "values": [],
        }
    }


@pytest.mark.filterwarnings(
    "ignore::urllib3.exceptions.InsecureRequestWarning", "ignore::pytest.PytestUnraisableExceptionWarning"
)
def test_add_watchlist_sends_real_booleans(mocker):
    """
    Given:
    - A request to create a watchlist.

    When:
    - The create-watchlist request body is built.

    Then:
    - "dynamic" and "enabled" are JSON booleans, not the strings "False"/"True". As strings both
      values are truthy, so a string "False" could enable a dynamic watchlist.
    """
    client, http_request = build_add_watchlist_client(mocker)
    client.args = {"name": "test_watchlist", "type": "IPAddress"}
    client.add_watchlist()

    watchlist = json.loads(http_request.call_args.kwargs["data"])["watchlist"]
    assert watchlist["dynamic"] is False
    assert watchlist["enabled"] is True
