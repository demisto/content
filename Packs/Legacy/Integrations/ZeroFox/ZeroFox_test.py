import json
import demistomock as demisto


def test_get_alert_contents(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://api.zerofox.com/1.0'
    })
    from ZeroFox import get_alert_contents
    with open('./TestData/alert.json') as f:
        alert_input = json.load(f)
    result = get_alert_contents(alert_input)
    with open('./TestData/alert_result.json') as f:
        expected_output = json.load(f)
    assert result == expected_output


def test_get_alert_contents_war_room(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://api.zerofox.com/1.0'
    })
    from ZeroFox import get_alert_human_readable_outputs
    with open('./TestData/alert_result.json') as f:
        contents_input = json.load(f)
    result = get_alert_human_readable_outputs(contents_input)
    with open('./TestData/contents_result.json') as f:
        expected_output = json.load(f)
    assert expected_output == result
