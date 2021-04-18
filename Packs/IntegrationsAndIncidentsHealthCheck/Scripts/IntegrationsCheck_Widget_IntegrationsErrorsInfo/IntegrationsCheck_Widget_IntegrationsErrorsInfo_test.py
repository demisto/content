import pytest
import demistomock as demisto
from IntegrationsCheck_Widget_IntegrationsErrorsInfo import main
from test_data.constants import FAILED_TABLE, FAILED_TABLE_EXPECTED


@pytest.mark.parametrize('list_, expected', [
    ([{'Contents': 'Item not found (8)'}], {'data': [{'Brand': None,
                                                      'Category': None,
                                                      'Information': None,
                                                      'Instance': None}],
                                            'total': 1}),
    ([{'Contents': FAILED_TABLE}], FAILED_TABLE_EXPECTED),
    ([{'Contents': ''}], {'data': [{'Brand': 'N/A',
                                    'Category': 'N/A',
                                    'Information': 'N/A',
                                    'Instance': 'N/A'}],
                          'total': 1}),
    ([{}], {'data': [{'Brand': 'N/A',
                      'Category': 'N/A',
                      'Information': 'N/A',
                      'Instance': 'N/A'}],
            'total': 1}),
])
def test_script(mocker, list_, expected):
    mocker.patch.object(demisto, 'executeCommand', return_value=list_)
    mocker.patch.object(demisto, 'results')

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected
