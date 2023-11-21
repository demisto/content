import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import *

QUERY_COMMAND_RESPONSE = [([{
    'Type': entryTypes['note'],
    'Contents': {'results': [
        {'test': 'test_value',
         'test2': 'test_value2'}
    ]}}], [{'test': 'test_value', 'test2': 'test_value2'}]),
    ([{
        'Type': entryTypes['note'],
        'Contents': {'results': []}}], 'No matches.')]


@pytest.mark.parametrize('res, contents', QUERY_COMMAND_RESPONSE)
def test_mimecast_find_email(res, contents, mocker):
    mocker.patch.object(demisto, 'executeCommand', return_value=res)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value={})

    from CBAlerts import main

    main()
    results = demisto.results.call_args[0][0]

    assert results[0].get('Contents') == contents
