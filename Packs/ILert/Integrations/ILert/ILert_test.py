import pytest
import demistomock as demisto

PARAMS = {'url': 'https://test.com', 'integrationKey': 'mock_key'}


@pytest.fixture(autouse=True)
def set_params(mocker):
    mocker.patch.object(demisto, 'params', return_value=PARAMS)


def test_submit_new_event_command(requests_mock):
    from ILert import submit_new_event_command
    kwargs = {
        'summary': 'mock_summary'
    }
    requests_mock.post('https://test.com/events', json={})
    result = submit_new_event_command(**kwargs)
    assert result == 'Incident has been created'


def test_submit_acknowledge_event_command(requests_mock):
    from ILert import submit_acknowledge_event_command
    kwargs = {
        'summary': 'mock_summary',
        'incident_key': 'mock_key'
    }
    requests_mock.post('https://test.com/events', json={})
    result = submit_acknowledge_event_command(**kwargs)
    assert result == 'Incident has been acknowledged'


def test_submit_resolve_event_command(requests_mock):
    from ILert import submit_resolve_event_command
    kwargs = {
        'summary': 'mock_summary',
        'incident_key': 'mock_key'
    }
    requests_mock.post('https://test.com/events', json={})
    result = submit_resolve_event_command(**kwargs)
    assert result == 'Incident has been resolved'
