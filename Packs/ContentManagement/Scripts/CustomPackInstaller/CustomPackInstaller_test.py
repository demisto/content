import pytest
from CommonServerPython import *


@pytest.mark.parametrize(
    argnames='skip_verify, skip_validation, uri',
    argvalues=[
        ('true', 'true', '/contentpacks/installed/upload?skipVerify=true&skipValidation=true'),
        ('false', 'true', '/contentpacks/installed/upload?skipValidation=true'),
        ('true', 'false', '/contentpacks/installed/upload?skipVerify=true'),
        ('false', 'false', '/contentpacks/installed/upload')
    ])
def test_build_url_parameters(mocker, skip_verify, skip_validation, uri):
    from CustomPackInstaller import build_url_parameters
    mocker.patch('CustomPackInstaller.is_demisto_version_ge', return_value=True)

    url_res = build_url_parameters(skip_verify, skip_validation)
    assert url_res == uri

    mocker.patch('CustomPackInstaller.is_demisto_version_ge', return_value=False)
    url_res = build_url_parameters(skip_verify, skip_validation)
    assert url_res == '/contentpacks/installed/upload'


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
    argnames='pack_id, context, err_massage, res',
    argvalues=[
        ('Pack1', {"File": [{"Name": "Pack1.zip", "EntryID": "1234"}]}, '', True),
        ('Pack2', {"File": [{"Name": "Pack2.zip", "EntryID": "abcd"}]}, '', True)
    ])
def test_install_custom_pack_success(mocker, pack_id, context, err_massage, res):
    from CustomPackInstaller import install_custom_pack

    mocker.patch.object(demisto, 'context', return_value=context)
    mocker.patch('CustomPackInstaller.execute_command', return_value=('Ok', ''))

    result, error_message = install_custom_pack(pack_id, 'true', 'true')
    assert result == res
    assert error_message == err_massage
