"""Qintel PMI Integration for Cortex XSOAR - Unit Tests file"""

import json
import io

MOCK_URL = 'https://this-is-only-a-test.local'
MOCK_CLIENT_ID = 'client-id'
MOCK_CLIENT_SECRET = 'client-secret'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_make_timestamp():

    from QintelPMI import _make_timestamp
    from datetime import datetime

    res = _make_timestamp(None)
    assert res is None

    res = _make_timestamp(1626211855)
    assert isinstance(res, datetime)
    assert res.isoformat() == '2021-07-13T21:30:55'

    res = _make_timestamp('2021-07-13T21:30:55')
    assert isinstance(res, datetime)
    assert int(res.timestamp()) == 1626211855


def test_test_module(mocker):
    """Tests cve reputation command function with valid response.

    Checks the output of the command function with the expected output.
    """

    from QintelPMI import Client, test_module

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/test_module.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    response = test_module(client)

    assert response == 'ok'


def test_cve_command(mocker):
    """Tests cve reputation command function with valid response.

    Checks the output of the command function with the expected output.
    """

    from QintelPMI import Client, cve_command

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/cve_command.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    args = {
        'cve': 'CVE-2021-0123'
    }

    response = cve_command(client, **args)

    assert len(response) == 1

    outputs = response[0].outputs
    hr = response[0].readable_output
    prefix = response[0].outputs_prefix

    assert prefix == 'Qintel.CVE'

    assert 'Qintel vulnerability results for: CVE-2021-0123' in hr
    assert 'Vulnerability in Example System affecting versions: 1.0, 1.1' in hr
    assert 'Last observed: 2021-07-13 09:31:09' in hr
    assert '|actor|actor_type|exploit_type|exploit_notes|date_observed|' in hr
    assert '| Unattributed Threat Actor | other | cve |' \
           '  | 2021-07-13 09:31:09 |' in hr

    assert outputs['id'] == 'CVE-2021-0123'
    assert outputs['AffectedSystem'] == 'Example System'
    assert outputs['AffectedVersions'] == '1.0, 1.1'
    assert outputs['LastObserved'] == '2021-07-13 09:31:09'
    assert len(outputs['Observations']) == 1
    assert outputs['Observations'][0]['actor'] == 'Unattributed Threat Actor'
    assert outputs['Observations'][0]['actor_type'] == 'other'
    assert outputs['Observations'][0]['exploit_type'] == 'cve'
    assert outputs['Observations'][0]['exploit_notes'] is None
    assert outputs['Observations'][0]['date_observed'] == '2021-07-13 09:31:09'


def test_cve_command_empty(mocker):
    """Tests cve reputation command function with empty response.

    Checks the output of the command function with the expected output.
    """
    from QintelPMI import Client, cve_command

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/cve_command_empty.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    args = {
        'cve': 'CVE-2021-0123'
    }

    response = cve_command(client, **args)

    assert len(response) == 1

    outputs = response[0].outputs
    hr = response[0].readable_output
    prefix = response[0].outputs_prefix

    assert prefix is None

    assert 'Qintel vulnerability results for: CVE-2021-0123' in hr
    assert 'Vulnerability in' not in hr
    assert 'Last observed:' not in hr
    assert '|actor|actor_type|exploit_type|exploit_notes|date_observed|' \
           not in hr

    assert outputs is None
