import json
import io

from CognyteLuminar import Client, cognyte_luminar_get_indicators, \
    cognyte_luminar_get_leaked_records, module_test, reset_last_run

client = Client(
    base_url="http://test.com",
    account_id="abcd1234",
    client_id="cognyte",
    client_secret="test",
    verify=False,
    proxy=False
)


def load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


INDICATOR_LIST = load_json("test_data/indicator_list.json")


def test_test_module(mocker):
    mocker.patch.object(client, 'fetch_access_token', autospec=True)
    response = module_test(client)
    assert response == "ok"


def test_cognyte_luminar_get_indicators(mocker):
    mocker.patch.object(client, 'get_luminar_indicators_list', side_effect=[INDICATOR_LIST])
    args = {"limit": 3}
    response = cognyte_luminar_get_indicators(client, args)
    assert len(response.outputs) == 3
    assert len(response.raw_response) == 3
    assert response.outputs_prefix == "Luminar.Indicators"


def test_cognyte_luminar_get_indicators_without_limit(mocker):
    mocker.patch.object(client, 'get_luminar_indicators_list', side_effect=[INDICATOR_LIST])
    args = {}
    response = cognyte_luminar_get_indicators(client, args)
    assert len(response.outputs) == 50
    assert len(response.raw_response) == 50
    assert response.outputs_prefix == "Luminar.Indicators"


def test_cognyte_luminar_get_leaked_records(mocker):
    mocker.patch.object(client, 'get_luminar_leaked_credentials_list',
                        side_effect=[INDICATOR_LIST])
    args = {
        "limit": 3
    }
    response = cognyte_luminar_get_leaked_records(client, args)

    assert len(response.outputs) == 3
    assert len(response.raw_response) == 3
    assert response.outputs_prefix == "Luminar.Leaked_Credentials"


def test_cognyte_luminar_get_leaked_records_without_limit(mocker):
    mocker.patch.object(client, 'get_luminar_leaked_credentials_list',
                        side_effect=[INDICATOR_LIST])
    args = {}
    response = cognyte_luminar_get_leaked_records(client, args)

    assert len(response.outputs) == 50
    assert len(response.raw_response) == 50
    assert response.outputs_prefix == "Luminar.Leaked_Credentials"


def test_reset_last_run(mocker):
    response = reset_last_run()
    assert response.readable_output == "Fetch history deleted successfully"
