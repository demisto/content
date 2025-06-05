from unittest.mock import MagicMock

import TakedownCyberint
import pytest
from CommonServerPython import DemistoException

BASE_URL = "https://feed-example.com"
TOKEN = "example_token"


@pytest.fixture()
def mock_client() -> TakedownCyberint.Client:
    """
    Establish a mock connection to the client with access token.

    Returns:
        Client: Mock connection to client.
    """
    return TakedownCyberint.Client(
        base_url=BASE_URL,
        access_token=TOKEN,
        verify=False,
        proxy=False,
    )


def test_test_module_forbidden_error(mock_client):
    """Test test_module with a forbidden error."""
    # Mock `retrieve_takedown_requests` to raise a DemistoException with FORBIDDEN status
    exception = DemistoException("Forbidden")
    exception.res = MagicMock(status_code=403)
    mock_client.retrieve_takedown_requests = MagicMock(side_effect=exception)

    result = TakedownCyberint.test_module(mock_client)

    assert result == "Authorization Error: invalid `API Token`"
    mock_client.retrieve_takedown_requests.assert_called_once_with(limit=10, test=True)


def test_test_module_unexpected_error(mock_client):
    """Test test_module with an unexpected error."""
    # Mock `retrieve_takedown_requests` to raise a generic DemistoException
    exception = DemistoException("Unexpected error")
    TakedownCyberint.Client.retrieve_takedown_requests = MagicMock(side_effect=exception)

    with pytest.raises(DemistoException, match="Unexpected error"):
        TakedownCyberint.test_module(mock_client)

    TakedownCyberint.Client.retrieve_takedown_requests.assert_called_once_with(limit=10, test=True)
