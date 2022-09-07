from MimecastFindEmail import main
import demistomock as demisto  # noqa: F401
from CommonServerPython import *

QUERY_COMMAND_RESPONSE = [{
    'Type': entryTypes['note'],
    'Contents': {'data': [
        {
            'items': [{'displayto': 'test1'},
                      {'displayto': 'test2'}]
        }
    ]}
}]


def test_mimecast_find_email(mocker):
    mocker.patch.object(demisto, 'executeCommand', return_value=QUERY_COMMAND_RESPONSE)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]

    assert results[0].get('Contents') == '### Mailboxes with email(s) matching the query:\n* test1\n* test2\n'
    assert results[1].get('Contents') == 'yes'