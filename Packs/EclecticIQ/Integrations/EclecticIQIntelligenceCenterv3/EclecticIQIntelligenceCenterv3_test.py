import pytest  # noqa: F401
from unittest.mock import patch, Mock  # noqa: F401
import demistomock as demisto  # noqa: F401
from EclecticIQIntelligenceCenterv3 import EclecticIQ_api, domain_command

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


@patch("EclecticIQIntelligenceCenterv3.eiq.lookup_observable")
@patch("EclecticIQIntelligenceCenterv3.eiq.create_entity")
@patch("EclecticIQIntelligenceCenterv3.return_results")
def test_domain_command(
    mock_return_results, mock_create_entity, mock_lookup_observable
):
    # Mocking Demisto args
    with patch("EclecticIQIntelligenceCenterv3.demisto.args", return_value={"domain": "example.com"}):
        # Mocking response from eiq.lookup_observable
        mock_lookup_observable.return_value = {
            "type": "domain",
            "reputation": "Malicious (High confidence)",
        }

        # Mocking the parse_reputation_results function
        with patch("EclecticIQIntelligenceCenterv3.parse_reputation_results") as mock_parse_reputation_results:
            mock_parse_reputation_results.return_value = {"result_key": "result_value"}
            domain_command()

            mock_lookup_observable.assert_called_with("example.com", "domain")
            mock_parse_reputation_results.assert_called_with(
                mock_lookup_observable.return_value,
                "example.com",
                "domain",
                "your_domain_threshold",
                "Domain",
            )

            mock_create_entity.assert_called_with(
                observable_dict=[
                    {
                        "observable_type": "domain",
                        "observable_value": "example.com",
                        "observable_maliciousness": "medium",
                        "observable_classification": "bad",
                    }
                ],
                source_group_name="your_group_name",
                entity_title="XSOAR automatic Sighting for example.com",
                entity_description="",
            )

            mock_return_results.assert_called_with({"result_key": "result_value"})

