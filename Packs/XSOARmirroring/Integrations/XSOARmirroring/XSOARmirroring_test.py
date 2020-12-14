from XSOARmirroring import get_mapping_fields_command


def generate_dummy_client():
    class Client:
        def __init__(self):
            pass

        def get_incident_fields(self):
            pass

        def get_incident_types(self):
            pass

    return Client


INCIDENT_FIELDS = [
    {
        'group': 0,
        'associatedToAll': True,
        'name': "field1",
        'type': 'type1',
        'description': 'description1',
        'cliName': 'cliName1'
    },
    {
        'group': 0,
        'associatedTypes': [
            "test"
        ],
        'name': "field2",
        'type': 'type2',
        'description': 'description2',
        'cliName': 'cliName2'
    }
]
INCIDENT_TYPES = [
    {
        "name": "Something"
    },
    {
        "name": "test"
    }
]


def test_mirroring(mocker):
    """
    Given:
        - Two incident types and fields.

    When:
        - one field is associated to all while the second is associated to one.

    Then:
        - A correct mapping dict is created, with a "Default Scheme" included
    """
    client = generate_dummy_client()
    mocker.patch.object(client, 'get_incident_fields', return_value=INCIDENT_FIELDS)
    mocker.patch.object(client, 'get_incident_types', return_value=INCIDENT_TYPES)
    response = get_mapping_fields_command(client).extract_mapping()
    assert len(response) == 3
    assert 'Default Mapping' in str(response)
    parsed_response = {}
    for mapping in response:
        parsed_response.update(mapping)
    assert parsed_response['Default Mapping'] == {
        'cliName1': 'field1 - type1'
    }
    assert parsed_response['test'] == {
        'cliName1': 'field1 - type1',
        'cliName2': 'field2 - type2'
    }
    assert parsed_response['Something'] == {
        'cliName1': 'field1 - type1'
    }
