import pytest  # noqa: F401
import demistomock as demisto  # noqa: F401
from EclecticIQIntelligenceCenterv3 import EclecticIQ_api

SERVER = "https://ic-playground.eclecticiq.com"
EIQ_USER = "test@test.test"
PASSWORD = "123"
EIQ_FEED_IDs = "12"
USE_SSL = "false"
API_VERSION = "v2"


@pytest.fixture
def mock_api_request(mocker):
    return mocker.patch.object(EclecticIQ_api, 'send_api_request', autospec=True)


def test_get_source_group_uid_success(mock_api_request, mocker):
    mock_api_request.return_value.json.return_value = {
        "data": [{"source": "mocked_source_id"}]
    }
    mocker.patch.object(EclecticIQ_api, 'eiq_logging')

    eiq_instance = EclecticIQ_api()

    result = eiq_instance.get_source_group_uid("mocked_group_name")
    assert result == "mocked_source_id"
    EclecticIQ_api.eiq_logging.debug.assert_called_with("Requesting source id for specified group, name=[mocked_group_name]")
    EclecticIQ_api.eiq_logging.debug.assert_any_call("Source group id received")
    EclecticIQ_api.eiq_logging.debug.assert_any_call("Source group id is: mocked_source_id")


def test_get_source_group_uid_failure(mock_api_request, mocker):
    mock_api_request.return_value.json.return_value = {"data": []}
    mocker.patch.object(EclecticIQ_api, 'eiq_logging')
    eiq_instance = EclecticIQ_api()
    result = eiq_instance.get_source_group_uid("nonexistent_group")
    assert result == "error_in_fetching_group_id"
    EclecticIQ_api.eiq_logging.error.assert_called_with(
        "Something went wrong fetching the group id. "
        "Please note the source group name is case sensitive! "
        "Received response: {'data': []}"
    )