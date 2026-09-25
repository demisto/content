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


@freeze_time(MOCK_CURRENT_TIME)
@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_alarm_to_incidents(mocker):
    """
    Given:
    - An integration instance configured to fetch incidents.

    When:
    - Running two intervals of fetch-incidents command, and:
       1. No alarms exist in the 3rd-party until the first run
       2. Two alarms are created in the 3rd-party between the first and the second run.

    Then:
    - Make sure the `time` field of the lastRun object that is sent as
       the start time of the alarms query is not updated after the first run.
    - Make sure two incidents are returned on the second run.
    - Make sure the `time` field of the lastRun object is updated correctly after
       the second run.

    """

    params = {
        "url": "https://example.com",
        "insecure": True,
        "credentials": {"identifier": "TEST", "password": "TEST"},
        "version": "11.6.11",
        "fetchTime": create_time_difference_string(days=3, hours=6),
        "startingFetchID": 0,
    }
    alarms = [
        {"id": 1, "triggeredDate": create_time_difference_string(hours=6)},
        {"id": 2, "triggeredDate": create_time_difference_string(hours=5)},
    ]

    def mock_fetch_alarams(since: str = None, start_time: str = None, end_time: str = None, raw: bool = False):
        if type(start_time) is str:
            start_time = datetime.strptime(start_time, McAfeeESMClient.demisto_format)
        all_alarms = [
            alarm
            for alarm in alarms
            if datetime.strptime(alarm.get("triggeredDate"), McAfeeESMClient.demisto_format) > start_time
        ]
        return None, None, all_alarms

    def mock_fetch_alarm_without_results(client):
        mocker.patch.object(McAfeeESMClient, "fetch_alarms", return_value=(None, None, []))
        try:
            client.fetch_incidents(params=params)
        except Exception:
            pass
        return demisto.setLastRun.call_args[0][0]

    mocker.patch("McAfee_ESM_v2.parse_date_range", return_value=["", ""])
    mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__set_session", return_value={})
    mocker.patch.object(McAfeeESMClient, "_McAfeeESMClient__request", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={"alarms": {"time": create_time_difference_string(days=3)}})
    mocker.patch.object(demisto, "setLastRun")

    try:
        client = McAfeeESMClient(params)

        last_run = mock_fetch_alarm_without_results(client)
        assert last_run.get("alarms").get("time") == create_time_difference_string(days=3)

        mocker.patch.object(demisto, "getLastRun", return_value=last_run)
        mocker.patch.object(McAfeeESMClient, "fetch_alarms", side_effect=mock_fetch_alarams)
        mocker.patch.object(demisto, "incidents")
        client.fetch_incidents(params=params)
    except Exception:
        pass
    incidents = demisto.incidents.call_args[0][0]
    last_run = demisto.setLastRun.call_args[0][0]

    assert len(incidents) == 2
    assert last_run.get("alarms").get("time") == create_time_difference_string(hours=5)


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
