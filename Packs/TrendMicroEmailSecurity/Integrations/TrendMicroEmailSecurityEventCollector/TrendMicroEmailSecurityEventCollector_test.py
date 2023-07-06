import pytest
from CommonServerPython import DemistoException
from TrendMicroEmailSecurityEventCollector import (
    Client,
    order_first_fetch,
    NoContentException,
)


@pytest.mark.parametrize("first_fetch", [("3 days"), ("32 hours")])
def test_order_first_fetch(first_fetch: str):
    assert order_first_fetch(first_fetch)


@pytest.mark.parametrize("first_fetch", [("7 days"), ("4321 minutes")])
def test_order_first_fetch_failure(first_fetch: str):
    with pytest.raises(
        ValueError,
        match="The request retrieves logs created within 72 hours at most before sending the request\n"
        "Please put in the First Fetch Time parameter a value that is at most 72 hours / 3 days",
    ):
        order_first_fetch(first_fetch)


def test_handle_error_no_content():
    client = Client(
        base_url="test", username="test", api_key="test", verify=False, proxy=False
    )

    class Response:
        status_code = 204

    with pytest.raises(NoContentException, match="No content"):
        client.handle_error_no_content(Response())


def test_handle_error_no_content_without_raises():
    client = Client(
        base_url="test", username="test", api_key="test", verify=False, proxy=False
    )

    class Response:
        status_code = 404
        reason = "test"

        def json(self):
            return {}

    with pytest.raises(DemistoException):
        client.handle_error_no_content(Response())
