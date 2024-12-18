import json


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_unauthorized_event_types():
    """
    Given:
        - JSON response from 'Auth introspect' endpoint and a list of configured event types.

    When:
        - Calling get_unauthorized_event_types.

    Assert:
        - Correct list of unauthorized event types.
    """
    from OnePasswordEventCollector import get_unauthorized_event_types

    event_types = ['Audit events', 'Item usage actions', 'Sign in attempts']
    mock_response = util_load_json('test_data/introspection_response.json')
    unauthorized_event_types = get_unauthorized_event_types(mock_response, event_types)
    assert list(unauthorized_event_types) == []
