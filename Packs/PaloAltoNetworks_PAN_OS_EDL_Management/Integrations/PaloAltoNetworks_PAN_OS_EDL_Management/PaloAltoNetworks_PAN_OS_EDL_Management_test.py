import pytest

from CommonServerPython import *


def test_get_external_file_too_many_new_lines(mocker):
    """
    Given:
     - an invalid file content with too many newlines

    When:
     - running edl_get_external_file_command

    Then:
     - Verify that an appropriate error message is shown to the user
     - Verify that ssh_execute was executed the correct amount of times
    """
    import PaloAltoNetworks_PAN_OS_EDL_Management as PANW_EDL
    invalid_file = 'a\nb\na\nn\ni\nb\ni\na\nb\no\nd\ne\nb\ne\n'
    mocker.patch.object(PANW_EDL, 'ssh_execute', return_value=invalid_file)
    err_msg = 'The file contains too many newlines to be valid. ' \
              'Please check the file contents on the external web server manually.'
    with pytest.raises(DemistoException, match=err_msg):
        PANW_EDL.edl_get_external_file_command(args={'file_path': 'lies', 'retries': '4'})

    assert PANW_EDL.ssh_execute.call_count == 4
