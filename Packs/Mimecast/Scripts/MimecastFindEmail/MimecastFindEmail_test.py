from MimecastFindEmail import main
import demistomock as demisto  # noqa: F401
from CommonServerPython import *
import pytest

QUERY_COMMAND_RESPONSE = [([{
    'Type': entryTypes['note'],
    'Contents': {'data': [
        {
            'items': [{'displayto': 'test1'},
                      {'displayto': 'test2'}]
        }
    ]}
}], 'yes', 1),
    ([{
        'Type': entryTypes['note'],
        'Contents': {'data': []}
    }], 'no', 0)
]


@pytest.mark.parametrize('res, res_str, res_num', QUERY_COMMAND_RESPONSE)
def test_mimecast_find_email(res, res_str, res_num, mocker):
    mocker.patch.object(demisto, 'executeCommand', return_value=res)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]

    if res_str == 'yes':
        assert '### Mailboxes with email(s) matching the query:' in results[0].get('Contents')
    assert results[res_num].get('Contents') == res_str
