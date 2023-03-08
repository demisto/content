import pytest
from CommonServerPython import *


@pytest.mark.parametrize(
    argnames='pack_id, context, err_massage, res',
    argvalues=[
        ('Pack1', {"File": [{"Name": "Pack1.zip", "EntryID": ""}]}, 'Could not find file entry ID.', False),
        ('Pack1', {"File": [{"Name": "Pack1.zip", "EntryID": "1234"}]},
         'Issue occurred while installing the pack on the machine.\n', False)
    ])
def test_install_custom_pack_failed(mocker, pack_id, context, err_massage, res):
    from CustomPackInstaller import install_custom_pack

    mocker.patch.object(demisto, 'context', return_value=context)
    mocker.patch('CustomPackInstaller.execute_command', return_value=('', ''))

    result, error_message = install_custom_pack(pack_id, 'true', 'true')
    assert result == res
    assert error_message == err_massage


@pytest.mark.parametrize(
    argnames='pack_id, context',
    argvalues=[
        ('Pack1', {"File": [{"Name": "Pack1.zip", "EntryID": "1234"}]}),
        ('Pack2', {"File": [{"Name": "Pack2.zip", "EntryID": "abcd"}]}),
        ('Pack1', {"File": [{"Name": "content/packs/Pack1/0.0.1/Pack1.zip", "EntryID": "1234"}]}),
        ('Pack2', {"File": [{"Name": "content/packs/Pack2/0.1.0/Pack2.zip", "EntryID": "abcd"}]})
    ])
def test_install_custom_pack_success(mocker, pack_id, context,):
    """
    Given  pack_id and context mock.
    - Case 1: given a pack with just a filename and numerical EntryID.
    - Case 2: given a pack with just a filename and alphabetical EntryID.
    - Case 3: given a pack with a full path name and numerical EntryID,
    - Case 4: given a pack with a full path name and alphabetical EntryID,

    When
    - Running install_custom_pack function.

    Then
    - Ensure the pack id is recognized and the function succeed.
    """
    from CustomPackInstaller import install_custom_pack

    mocker.patch.object(demisto, 'context', return_value=context)
    mocker.patch('CustomPackInstaller.execute_command', return_value=('Ok', ''))

    result, error_message = install_custom_pack(pack_id, 'true', 'true')
    assert result
    assert error_message == ''


def test_install_custom_pack_specify_instance(mocker):
    from CustomPackInstaller import install_custom_pack
    context = {"File": [{"Name": "Pack1.zip", "EntryID": "1234"}]}

    mocker.patch.object(demisto, 'context', return_value=context)
    execute_command_mock = mocker.patch('CustomPackInstaller.execute_command', return_value=('Ok', ''))

    _, _ = install_custom_pack('Pack1', 'true', 'true', 'instance1')
    execute_command_args = execute_command_mock.call_args_list[0][0]
    assert execute_command_args[1]['using'] == 'instance1'


def test_install_custom_pack_no_specify_instance(mocker):
    from CustomPackInstaller import install_custom_pack
    context = {"File": [{"Name": "Pack1.zip", "EntryID": "1234"}]}

    mocker.patch.object(demisto, 'context', return_value=context)
    execute_command_mock = mocker.patch('CustomPackInstaller.execute_command', return_value=('Ok', ''))

    _, _ = install_custom_pack('Pack1', 'true', 'true')
    execute_command_args = execute_command_mock.call_args_list[0][0]
    assert 'using' not in execute_command_args[1].keys()
