import BreachRx
from BreachRx import (
    BreachRxClient,
    create_incident_command,
    get_incident_actions_command,
    import_incident_command,
    get_incident_command,
    get_incident_types,
    get_incident_severities,
    create_incident_mutation,
    get_incident_by_name,
    get_actions_for_incident
)

import io
from CommonServerPython import json
import requests_mock
from graphql.language import print_ast
import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def introspection_matcher(request):
    if "IntrospectionQuery" in request.json().get('query'):
        return True
    return False


def create_incident_matcher(request):
    if request.json().get('query') == print_ast(create_incident_mutation):
        return True
    return False


def get_severities_matcher(request):
    if request.json().get('query') == print_ast(get_incident_severities):
        return True
    return False


def get_types_matcher(request):
    if request.json().get("query") == print_ast(get_incident_types):
        return True
    return False


def get_incident_matcher(request):
    if request.json().get("query") == print_ast(get_incident_by_name):
        return True
    return False


def get_actions_matcher(request):
    if request.json().get("query") == print_ast(get_actions_for_incident):
        return True
    return False


def set_up_mocker(m, found_incident=True):
    m.post(
        requests_mock.ANY,
        additional_matcher=create_incident_matcher,
        json=util_load_json("test_data/create_incident.json")
    )
    m.post(
        requests_mock.ANY,
        additional_matcher=get_severities_matcher,
        json=util_load_json("test_data/incident_severities.json")
    )
    m.post(
        requests_mock.ANY,
        additional_matcher=get_types_matcher,
        json=util_load_json("test_data/incident_types.json")
    )
    if found_incident:
        m.post(
            requests_mock.ANY,
            additional_matcher=get_incident_matcher,
            json=util_load_json("test_data/get_incident.json")
        )
    else:
        m.post(
            requests_mock.ANY,
            additional_matcher=get_incident_matcher,
            json=util_load_json("test_data/get_incident_empty.json")
        )
    m.post(
        requests_mock.ANY,
        additional_matcher=get_actions_matcher,
        json=util_load_json("test_data/get_actions_for_incident.json")
    )

    return BreachRxClient("mock://base_url", "api_key", "secret_key", "org_name", False)


def test_create_incident_command():
    incident_name = "this is an incident"
    incident_description = "Here is a description."

    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        results = create_incident_command(
            client,
            incident_name=incident_name,
            description=incident_description
        )

        create_incident_request = m.request_history[-1]
        assert incident_name == create_incident_request.json()['variables']['name']
        assert incident_description == create_incident_request.json()['variables']['description']

    assert results.outputs_prefix == "BreachRx.Incident"
    assert results.outputs_key_field == "id"
    assert results.outputs == {
        'description': 'This is a description.',
        'id': 369,
        'identifier': 'JULIETT000369',
        'name': 'a random incident to create',
        'severity': {'name': 'Unknown'},
        'types': [{'type': {'name': 'Other'}}],
    }


def test_create_incident_command_no_description():
    incident_name = "this is an incident"

    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        results = create_incident_command(
            client,
            incident_name=incident_name
        )

        create_incident_request = m.request_history[-1]
        assert incident_name == create_incident_request.json()['variables']['name']
        assert """An Incident copied from the Palo Alto Networks XSOAR platform.
            <br>
            <br>
            XSOAR Incident Name: 1""" == create_incident_request.json()['variables']['description']

    assert results.outputs_prefix == "BreachRx.Incident"
    assert results.outputs_key_field == "id"
    assert results.outputs == {
        'description': 'This is a description.',
        'id': 369,
        'identifier': 'JULIETT000369',
        'name': 'a random incident to create',
        'severity': {'name': 'Unknown'},
        'types': [{'type': {'name': 'Other'}}],
    }


def test_create_incident_command_no_incident_name():
    incident_description = "Here is a description."

    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        results = create_incident_command(
            client,
            description=incident_description
        )

        create_incident_request = m.request_history[-1]
        assert "1" == create_incident_request.json()['variables']['name']
        assert incident_description == create_incident_request.json()['variables']['description']

    assert results.outputs_prefix == "BreachRx.Incident"
    assert results.outputs_key_field == "id"
    assert results.outputs == {
        'description': 'This is a description.',
        'id': 369,
        'identifier': 'JULIETT000369',
        'name': 'a random incident to create',
        'severity': {'name': 'Unknown'},
        'types': [{'type': {'name': 'Other'}}],
    }


def test_get_incident_actions_command(mocker):
    incident = {
        "id": 339,
        "name": "4 My manually set XSOAR Incident name",
        "severity": {
            "name": "High"
        },
        "types": [
            {
                "type": {
                    "name": "Attempted Access"
                }
            }
        ],
        "description": "An alternative description!",
        "identifier": "JULIETT000339"
    }

    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        mocker.patch.object(BreachRx, "demisto")
        BreachRx.demisto.dt.return_value = incident
        results = get_incident_actions_command(client)

    get_actions_request = m.request_history[-1]
    assert get_actions_request.json()['variables'].get("incidentId") == incident["id"]

    assert results.outputs_prefix == "BreachRx.Incident"
    assert results.outputs_key_field == "id"
    assert results.outputs == [{
        'description': 'An alternative description!',
        'id': 339,
        'identifier': 'JULIETT000339',
        'name': '4 My manually set XSOAR Incident name',
        'severity': {'name': 'High'},
        'types': [{'type': {'name': 'Attempted Access'}}],
        'actions': [
            {
                'description': '<p>abc</p>',
                'id': 1229,
                'name': 'Another ggg',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1230,
                'name': 'conditions',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1231,
                'name': 'make another task',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '<p style"margin-left: 25px;">test indent</p>',
                'id': 1232,
                'name': 'test4',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
        ]
    }]


def test_get_incident_actions_command_no_incident_context():
    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        with pytest.raises(Exception) as error:
            get_incident_actions_command(client)

    assert str(error.value) == (
        "Error: No BreachRx privacy Incident associated with this Incident,"
        " and no Incident search terms provided."
    )


def test_get_incident_actions_command_incident_name(mocker):
    incident_name = "Random Incident Name"
    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        results = get_incident_actions_command(
            client,
            incident_name=incident_name
        )
        get_incident_request = m.request_history[-2]
        assert get_incident_request.json()['variables'].get('name') == incident_name

        get_actions_request = m.request_history[-1]
        assert get_actions_request.json()['variables'].get("incidentId") == 339

    assert results.outputs_prefix == "BreachRx.Incident"
    assert results.outputs_key_field == "id"
    assert results.outputs == [{
        'description': 'An alternative description!',
        'id': 339,
        'identifier': 'JULIETT000339',
        'name': '4 My manually set XSOAR Incident name',
        'severity': {'name': 'High'},
        'types': [{'type': {'name': 'Attempted Access'}}],
        'actions': [
            {
                'description': '<p>abc</p>',
                'id': 1229,
                'name': 'Another ggg',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1230,
                'name': 'conditions',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1231,
                'name': 'make another task',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '<p style"margin-left: 25px;">test indent</p>',
                'id': 1232,
                'name': 'test4',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
        ]
    }]


def test_get_incident_actions_command_incident_identifier():
    incident_identifier = "TEST0001"
    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        results = get_incident_actions_command(
            client,
            incident_identifier=incident_identifier
        )
        get_incident_request = m.request_history[-2]
        assert get_incident_request.json()['variables'].get('identifier') == incident_identifier

        get_actions_request = m.request_history[-1]
        assert get_actions_request.json()['variables'].get("incidentId") == 339

    assert results.outputs_prefix == "BreachRx.Incident"
    assert results.outputs_key_field == "id"
    assert results.outputs == [{
        'description': 'An alternative description!',
        'id': 339,
        'identifier': 'JULIETT000339',
        'name': '4 My manually set XSOAR Incident name',
        'severity': {'name': 'High'},
        'types': [{'type': {'name': 'Attempted Access'}}],
        'actions': [
            {
                'description': '<p>abc</p>',
                'id': 1229,
                'name': 'Another ggg',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1230,
                'name': 'conditions',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1231,
                'name': 'make another task',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '<p style"margin-left: 25px;">test indent</p>',
                'id': 1232,
                'name': 'test4',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
        ]
    }]


def test_get_incident_actions_command_multiple_incidents(mocker):
    incidents = [{
        "id": 339,
        "name": "4 My manually set XSOAR Incident name",
        "severity": {
            "name": "High"
        },
        "types": [
            {
                "type": {
                    "name": "Attempted Access"
                }
            }
        ],
        "description": "An alternative description!",
        "identifier": "JULIETT000339"
    }, {
        "id": 369,
        "name": "a random incident to create",
        "severity": {
            "name": "Unknown"
        },
        "types": [
            {
                "type": {
                    "name": "Other"
                }
            }
        ],
        "description": "This is a description.",
        "identifier": "JULIETT000369"
    }]

    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        mocker.patch.object(BreachRx, "demisto")
        BreachRx.demisto.dt.return_value = incidents
        results = get_incident_actions_command(client)

    get_actions_request = m.request_history[-2]
    assert get_actions_request.json()['variables'].get("incidentId") == incidents[0]["id"]

    get_actions_request = m.request_history[-1]
    assert get_actions_request.json()['variables'].get("incidentId") == incidents[1]["id"]

    assert results.outputs_prefix == "BreachRx.Incident"
    assert results.outputs_key_field == "id"
    assert results.outputs == [{
        'description': 'An alternative description!',
        'id': 339,
        'identifier': 'JULIETT000339',
        'name': '4 My manually set XSOAR Incident name',
        'severity': {'name': 'High'},
        'types': [{'type': {'name': 'Attempted Access'}}],
        'actions': [
            {
                'description': '<p>abc</p>',
                'id': 1229,
                'name': 'Another ggg',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1230,
                'name': 'conditions',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1231,
                'name': 'make another task',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '<p style"margin-left: 25px;">test indent</p>',
                'id': 1232,
                'name': 'test4',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
        ]
    }, {
        "id": 369,
        "name": "a random incident to create",
        "description": "This is a description.",
        "identifier": "JULIETT000369",
        'severity': {'name': 'Unknown'},
        'types': [{'type': {'name': 'Other'}}],
        'actions': [
            {
                'description': '<p>abc</p>',
                'id': 1229,
                'name': 'Another ggg',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1230,
                'name': 'conditions',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '',
                'id': 1231,
                'name': 'make another task',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
            {
                'description': '<p style"margin-left: 25px;">test indent</p>',
                'id': 1232,
                'name': 'test4',
                'phase': {'id': 1, 'name': 'Ready'},
                'phase_name': 'Ready',
                'user': None
            },
        ]
    }]


def test_import_incident_command():
    incident_name = "This is another example Incident"
    incident_identifier = "FOO00123"

    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        results = import_incident_command(
            client,
            incident_name=incident_name,
            incident_identifier=incident_identifier
        )

        create_incident_request = m.request_history[-1]
        assert incident_name == create_incident_request.json()['variables']['name']
        assert incident_identifier == create_incident_request.json()['variables']['identifier']

    assert results.outputs_prefix == "BreachRx.Incident"
    assert results.outputs_key_field == "id"
    assert results.outputs == {
        'description': 'An alternative description!',
        'id': 339,
        'identifier': 'JULIETT000339',
        'name': '4 My manually set XSOAR Incident name',
        'severity': {'name': 'High'},
        'types': [{'type': {'name': 'Attempted Access'}}],
    }


def test_import_incident_command_no_incident():
    incident_name = "This is another example Incident"
    incident_identifier = "FOO00123"

    with requests_mock.Mocker() as m:
        client = set_up_mocker(m, found_incident=False)
        with pytest.raises(Exception) as error:
            import_incident_command(
                client,
                incident_name=incident_name,
                incident_identifier=incident_identifier
            )

        create_incident_request = m.request_history[-1]
        assert incident_name == create_incident_request.json()['variables']['name']
        assert incident_identifier == create_incident_request.json()['variables']['identifier']

    assert str(error.value) == "Error: No BreachRx privacy Incident found using the search terms provided."


def test_get_incident_command():
    incident_name = "This is another example Incident"
    incident_identifier = "FOO00123"

    with requests_mock.Mocker() as m:
        client = set_up_mocker(m)
        results = get_incident_command(
            client,
            incident_name=incident_name,
            incident_identifier=incident_identifier
        )

        create_incident_request = m.request_history[-1]
        assert incident_name == create_incident_request.json()['variables']['name']
        assert incident_identifier == create_incident_request.json()['variables']['identifier']

    assert results.readable_output == \
        'Incident found with name="4 My manually set XSOAR Incident name" and identifier="JULIETT000339".'


def test_get_incident_command_no_incident():
    incident_name = "This is another example Incident"
    incident_identifier = "FOO00123"

    with requests_mock.Mocker() as m:
        client = set_up_mocker(m, found_incident=False)
        results = get_incident_command(
            client,
            incident_name=incident_name,
            incident_identifier=incident_identifier
        )

        create_incident_request = m.request_history[-1]
        assert incident_name == create_incident_request.json()['variables']['name']
        assert incident_identifier == create_incident_request.json()['variables']['identifier']

    assert results == "No Incident found with those search terms."
