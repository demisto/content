import sys

import pytest

import demistomock as demisto  # noqa: F401
from ATDDetonate import main


@pytest.mark.parametrize("response, expected_output",
                         [
                             ([{"Type": "Results", "Contents": {"results": {}}}], "Coudn't extract TaskID from upload"),
                             ([{"Type": "Results", "Contents": {"results": [{"taskId": "-1"}]}}],
                              "File type not supported")
                         ]
                         )
def test_exit_on_error(mocker, response, expected_output):
    mocker.patch.object(demisto, 'executeCommand', return_value=response)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(sys, 'exit', side_effect=Exception('mock exit'))
    try:
        main()
    except Exception as exp:
        assert str(exp) == 'mock exit'
        assert demisto.results.call_args[0][0]['Contents'] == expected_output


def test_polling(mocker):
    atd_file_upload_resp = [{"Type": "Results", "Contents": {"results": [{"taskId": "1"}]}}]
    atd_check_status_resp = [[{"Type": "Results", "Contents": {"results": {"status": "1"}}}],
                             [{"Type": "Results", "Contents": {"results": {"status": "1", "istate": "1"}}}]]
    atd_get_report_resp = {"Type": "Results", "Contents": "Success!"}
    responses = [atd_file_upload_resp, atd_check_status_resp[0], atd_check_status_resp[1], atd_get_report_resp]
    mocker.patch.object(demisto, 'args', return_value={"interval": "1"})
    mocker.patch.object(demisto, 'executeCommand', side_effect=responses)
    mocker.patch.object(demisto, 'results')
    main()

    assert demisto.results.call_args[0][0]['Contents'] == "Success!"
