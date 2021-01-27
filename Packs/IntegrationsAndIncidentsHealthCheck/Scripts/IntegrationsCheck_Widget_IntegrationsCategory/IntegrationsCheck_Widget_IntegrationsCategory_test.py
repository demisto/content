import pytest
import demistomock as demisto
from IntegrationsCheck_Widget_IntegrationsCategory import main, random


@pytest.mark.parametrize('list_, expected', [
    ([{
        'Contents': 'Data Enrichment & Threat Intelligence,Vulnerability Management,Endpoint,Forensics & Malware '
                    'Analysis,Data Enrichment & Threat Intelligence,Endpoint'}],
     ('[{"data": [2], "name": "Data Enrichment & Threat Intelligence", "color": '
      '"#3e8"}, {"data": [2], "name": "Endpoint", "color": "#3e8"}, {"data": [1], '
      '"name": "Vulnerability Management", "color": "#3e8"}, {"data": [1], "name": '
      '"Forensics & Malware Analysis", "color": "#3e8"}]')),
    ([{'Contents': ''}], '[{"data": [0], "name": "N\\\\A", "color": "#00CD33"}]'),
    ([{}], '[{"data": [0], "name": "N\\\\A", "color": "#00CD33"}]'),
])
def test_script(mocker, list_, expected):
    mocker.patch.object(random, 'randint', return_value=1000)
    mocker.patch.object(demisto, 'executeCommand', return_value=list_)
    mocker.patch.object(demisto, 'results')

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected
