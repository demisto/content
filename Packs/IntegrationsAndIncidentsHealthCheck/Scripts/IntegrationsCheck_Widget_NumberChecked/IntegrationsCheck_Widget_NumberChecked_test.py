import pytest
import demistomock as demisto
from IntegrationsCheck_Widget_NumberChecked import main


@pytest.mark.parametrize(
    "list_, expected",
    [
        (
            [
                {
                    "Contents": "Cortex XDR - IR_instance_1,Core REST API_instance_1,Image "
                    "OCR_default_instance,Rasterize_default_instance,Where is the egg?_default_instance,d2,"
                    "fcm_default_instance,testmodule,Active Directory Query v2_instance_1,BigFix_instance_1,"
                    "Tanium Threat Response_instance_1,Threat Grid_instance_1,VirusTotal_instance_1,"
                    "remoteaccess_instance_1"
                }
            ],
            14,
        ),
        ([{"Contents": ""}], 0),
        ([{}], 0),
    ],
)
def test_script(mocker, list_, expected):
    mocker.patch.object(demisto, "executeCommand", return_value=list_)
    mocker.patch.object(demisto, "results")

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected
