
import pytest

from Tessian import format_url, Client, get_events_command

#  region HELPERS


def create_mock_client():
    return Client(
        base_url='https://api.example.com',
        verify=False,
        headers={
            'Authentication': 'API-Token some_api_key'
        }
    )

#  endregion


def test_get_events_command(mocker):
    """
    Tests the get_events_command function.

    No mock is needed here because the get_events_command does not call
    any external API.
    """

    #  Mock the client
    client = create_mock_client()
    client_mock = mocker.patch.object(
        client,
        'get_events',
        return_value={
            'checkpoint': "dummy_checkpoint",
            'additional_results': True,
            'results': {
                "dummy_key": "dummy_value"
            },
        }
    )

    input = {
        "limit": 10,
        "after_checkpoint": None,
        "created_after": None,
    }

    response = get_events_command(client, input)

    assert response.outputs == {
        "checkpoint": "dummy_checkpoint",
        "additional_results": True,
        "results": {
            "dummy_key": "dummy_value",
        }
    }

    assert client_mock.assert_called_with(10, None, None)


@pytest.mark.parametrize(
    """
    input_url, formatted_url
    """,
    [
        pytest.param(
            'https://test.com',
            'https://test.com',
            id='valid url given'
        ),
        pytest.param(
            'http://test.com',
            'https://test.com',
            id='http:// prefix given'
        ),
        pytest.param(
            'test.com',
            'https://test.com',
            id='no prefix given'
        ),
        pytest.param(
            'https://test.com/',
            'https://test.com',
            id='trailing slash given'
        ),
        pytest.param(
            'https://test.com/api/v1/test',
            'https://test.com',
            id='trailing url path given'
        ),
        pytest.param(
            'http://test.com/incorrect_api',
            'https://test.com',
            id='combination of incorrect prefix and suffix'
        ),
    ]
)
def test_format_url(input_url, formatted_url):
    assert formatted_url == format_url(input_url)
