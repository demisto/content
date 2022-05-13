"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

"""
import demistomock as demisto
import json
import io
from PenfieldAssign import penfield_assign, main
# from pytest import *


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# DUMMY DATA
fake_analyst_ids = 'admin,person'
fake_category = 'fake_cat'
fake_created = 'fake_date'
fake_id = 'fake_id'
fake_name = 'fake_name'
fake_severity = 'Low'


# TODO: REMOVE the following dummy unit test function

fake_response = [{
    'Contents': 'test_user'
}]


def test_penfield_assign(mocker):
    # this overwrite the command call
    mocker.patch.object(demisto, 'executeCommand', return_value=fake_response)
    assert penfield_assign(
        analyst_ids=fake_analyst_ids,
        category=fake_category,
        created=fake_created,
        id=fake_id,
        name=fake_name,
        severity=fake_severity
    ) == fake_response


def test_main(mocker):
    mock_users = util_load_json('test_data/test_2_users.json')
    mock_incident = util_load_json('test_data/test_incident.json')
    # overwrite get users, incidents, and args
    mocker.patch.object(demisto, 'executeCommand', return_value=mock_users)
    mocker.patch.object(demisto, 'incidents', return_value=mock_incident)
    mocker.patch.object(demisto, 'args', return_value={'assign': "No"})
    mocker.patch('PenfieldAssign.penfield_assign', return_value=fake_response)
    mocker.patch.object(demisto, 'results')

    main()

    assert demisto.results.call_args.args[0] == 'penfield suggests: test_user'
