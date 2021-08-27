import pytest
import demistomock as demisto
from IntegrationsCheck_Widget_NumberFailingInstances import main


@pytest.mark.parametrize('list_, expected', [
    ([{
        'Contents': 'Active Directory Query v2_instance_1,BigFix_instance_1,Tanium Threat Response_instance_1,'
                    'Threat Grid_instance_1,VirusTotal_instance_1,remoteaccess_instance_1'}],
     6),
    ([{'Contents': ''}], 0),
    ([{'Contents': 'Item not found (8)'}], 0),
    ([{}], 0)
])
def test_script(mocker, list_, expected):
    mocker.patch.object(demisto, 'executeCommand', return_value=list_)
    mocker.patch.object(demisto, 'results')

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected
