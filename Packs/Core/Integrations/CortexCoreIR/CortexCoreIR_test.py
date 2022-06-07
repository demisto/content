import json

Core_URL = 'https://api.xdrurl.com'


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_report_incorrect_wildfire_command(mocker):
    """
    Given:
        - FilterObject and name to get by exclisions.
    When
        - A user desires to get exclusions.
    Then
        - returns markdown, context data and raw response.
    """
    from CortexCoreIR import report_incorrect_wildfire_command, Client
    wildfire_response = load_test_data('./test_data/wildfire_response.json')
    mock_client = Client(base_url=f'{Core_URL}/public_api/v1', headers={})
    mocker.patch.object(mock_client, 'report_incorrect_wildfire', return_value=wildfire_response)
    file_hash = "11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252"
    args = {
        "email": "a@a.gmail.com",
        "file_hash": file_hash,
        "new_verdict": 0,
        "reason": "test1"
    }
    res = report_incorrect_wildfire_command(client=mock_client, args=args)
    assert res.readable_output == f'Reported incorrect WildFire on {file_hash}'
