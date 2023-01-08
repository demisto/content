import demistomock as demisto
from MicrosoftDefenderForCloudEventCollector import *
from datetime import datetime
import json
import random
import copy

ALL_ALERTS_JSON_PATH = 'test_data/all_alerts.json'
ALERTS_TO_SORT = 'test_data/alerts_to_sort.json'

client = MsClient(
    server="url", tenant_id="tenant", auth_id="auth_id", enc_key="enc_key", app_name="APP_NAME", verify="verify",
    proxy="proxy", self_deployed="self_deployed", subscription_id="subscription_id", ok_codes=(1, 3),
    certificate_thumbprint=None, private_key=None)

def read_json_util(path: str):
    with open(path, 'r') as f:
        json_file = json.load(f)
    
    return json_file

def test_find_next_run():
    assert find_next_run() == 0


def test_handle_last_run(mocker):
    mocker.patch.object(demisto, 'getLastRun', return_value='2023-01-01T15:35:51.179633Z')
    assert '2023-01-01T15:35:51.179633Z' == handle_last_run({})


def test_handle_last_run_first_fetch_time(mocker):
    t = datetime(year=2023, month=1, day=8, hour=14, minute=44, second=5)
    mocker.patch('MicrosoftDefenderForCloudEventCollector.arg_to_datetime', return_value = t)
    assert '2023-01-08T14:44:05.000000Z' == handle_last_run({'first_fetch': 123})

def test_get_events(mocker):
    mocker.patch(MsClient, 'get_event_list', return_value=read_json_util(ALL_ALERTS_JSON_PATH))
    get_events(client, 'fake_last_run', {'limit' : 30})


def test_sort_events(mocker):
    alerts_list = read_json_util(ALERTS_TO_SORT)
    backup_list = copy.deepcopy(alerts_list)
    random.shuffle(alerts_list)
    sort_events(alerts_list)
    assert alerts_list ==  backup_list
