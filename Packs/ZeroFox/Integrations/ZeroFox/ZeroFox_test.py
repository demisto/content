import os
import json
import demistomock as demisto

cwd = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(cwd, 'TestData')


def test_get_alert_contents(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://api.zerofox.com/1.0'
    })
    from ZeroFox import get_alert_contents
    alerts_file_path = os.path.join(test_data_path, 'alert.json')
    with open(alerts_file_path) as f:
        alert_input = json.load(f)
    result = get_alert_contents(alert_input)
    alert_result_file_path = os.path.join(test_data_path, 'alert_result.json')
    with open(alert_result_file_path) as f:
        expected_output = json.load(f)
    assert result == expected_output


def test_get_alert_contents_war_room(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://api.zerofox.com/1.0'
    })
    from ZeroFox import get_alert_human_readable_outputs
    alert_result_file_path = os.path.join(test_data_path, 'alert_result.json')
    with open(alert_result_file_path) as f:
        contents_input = json.load(f)
    result = get_alert_human_readable_outputs(contents_input)
    contents_result_file_path = os.path.join(test_data_path, 'contents_result.json')
    with open(contents_result_file_path) as f:
        expected_output = json.load(f)
    assert expected_output == result
