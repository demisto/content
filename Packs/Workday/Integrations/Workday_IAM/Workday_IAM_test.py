import demistomock as demisto  # noqa: F401
import io
import json

from Workday_IAM import Client, fetch_incidents
from test_data.event_results import events_result

EVENT_RESULTS = events_result


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents(mocker):
    """Unit test
    Given
    - raw response of report results
    When
    - mock the demisto map object
    - mock getting demisto indicators
    Then
    - validate the incidents values
    """
    client_response = util_load_json('test_data/json_raw_response.json')
    mapped_user = util_load_json('test_data/mapped_user.json')

    mocker.patch.object(Client, 'get_full_report', return_value=client_response)
    mocker.patch('Workday_IAM.get_all_user_profiles', return_value=("id", "mail"))
    mocker.patch.object(demisto, 'mapObject', return_value=mapped_user)
    client = Client(base_url="", verify="verify", headers={}, proxy=False, ok_codes=(200, 204), auth=None)

    fetch_events = fetch_incidents(client, {}, "")
    assert fetch_events == EVENT_RESULTS
