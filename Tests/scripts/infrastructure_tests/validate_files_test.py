from Tests.scripts.validate_files import FilesValidator


# from Tests.scripts.hook_validations.conf_json import ConfJsonValidator


def packagify_mock_no_change(modified, added, removed, tag):
    return modified, added, removed


def test_get_modified_files_packagify(mocker):
    mocker.patch('Tests.scripts.hook_validations.conf_json.ConfJsonValidator.load_conf_file', return_value={})
    file_validator = FilesValidator()

    changed_files = '''A       Integrations/Recorded_Future/CHANGELOG.md
    A       Integrations/Recorded_Future/Recorded_Future.py
    A       Integrations/Recorded_Future/Recorded_Future.yml
    A       Integrations/Recorded_Future/Recorded_Future_image.png
    D       Integrations/integration-Recorded_Future.yml'''

    mocker.patch('Tests.test_utils.get_remote_file', return_value={'name': 'Recorded Future'})
    # in python 3, this should be 'builtins.open'
    mocker.patch('__builtin__.open', mocker.mock_open(read_data="{'name': 'Recorded Future'}"))
    modified, added, deleted, old_format = file_validator.get_modified_files(changed_files)
    assert len(modified) == 1
    assert ('Integrations/integration-Recorded_Future.yml',
            'Integrations/Recorded_Future/Recorded_Future.yml') in modified
    assert len(added) == 0
    assert len(deleted) == 0


def test_get_modified_files_packs(mocker):
    mocker.patch('Tests.scripts.hook_validations.conf_json.ConfJsonValidator.load_conf_file', return_value={})
    file_validator = FilesValidator()

    changed_files = '''A       Packs/CortexXDR/CHANGELOG.md
    A       Packs/CortexXDR/Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.py
    A       Packs/CortexXDR/Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.py
    A       Packs/CortexXDR/Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR_image.png
    D       Integrations/PaloAltoNetworks_XDR/PaloAltoNetworks_XDR.py
    '''

    mocker.patch('Tests.test_utils.get_remote_file', return_value={'name': 'Cortex XDR - IR'})
    # in python 3, this should be 'builtins.open'
    mocker.patch('__builtin__.open', mocker.mock_open(read_data="{'name': 'Cortex XDR - IR}"))
    modified, added, deleted, old_format = file_validator.get_modified_files(changed_files)
    assert len(modified) == 1
    assert ('Integrations/integration-Recorded_Future.yml',
            'Integrations/Recorded_Future/Recorded_Future.yml') in modified
    assert len(added) == 0
    assert len(deleted) == 0


def test_get_modified_files_without_packagify(mocker):
    mocker.patch('Tests.scripts.hook_validations.conf_json.ConfJsonValidator.load_conf_file', return_value={})
    file_validator = FilesValidator()

    changed_files = '''A       Integrations/Recorded_Future/CHANGELOG.md
A       Integrations/Recorded_Future/Recorded_Future.py
A       Integrations/Recorded_Future/Recorded_Future.yml
A       Integrations/Recorded_Future/Recorded_Future_image.png
D       Integrations/integration-Recorded_Future.yml'''

    mocker.patch('Tests.scripts.validate_files.filter_packagify_changes', side_effect=packagify_mock_no_change)
    modified, added, deleted, old_format = file_validator.get_modified_files(changed_files)
    assert len(modified) == 0
    assert len(added) == 1
    assert 'Integrations/Recorded_Future/Recorded_Future.yml' in added
    assert len(deleted) == 1
    assert 'Integrations/integration-Recorded_Future.yml' in deleted

    changed_files = 'R100       Integrations/Recorded_Future/Recorded_Future.yml ' \
                    'Integrations/Recorded_Future/test_data/Recorded_Future.yml'
    modified, added, deleted, old_format = file_validator.get_modified_files(changed_files)
    assert len(modified) == 0
    assert len(added) == 0
    assert len(deleted) == 0

    changed_files = 'R100       Integrations/Recorded_Future_v2/Recorded_Future.py ' \
                    'Integrations/Recorded_Future/Recorded_Future.py'
    modified, added, deleted, old_format = file_validator.get_modified_files(changed_files)
    assert len(modified) == 1
    assert 'Integrations/Recorded_Future/Recorded_Future.yml' in modified
    assert len(added) == 0
    assert len(deleted) == 0

    changed_files = 'R34       Integrations/Recorded_Future/Recorded_Future_v2.yml ' \
                    'Integrations/Recorded_Future/Recorded_Future.yml'
    modified, added, deleted, old_format = file_validator.get_modified_files(changed_files)
    assert len(modified) == 1
    assert ('Integrations/Recorded_Future/Recorded_Future_v2.yml',
            'Integrations/Recorded_Future/Recorded_Future.yml') in modified
    assert len(added) == 0
    assert len(deleted) == 0

    changed_files = 'A       Integrations/Recorded_Future/some_yml.yml'
    modified, added, deleted, old_format = file_validator.get_modified_files(changed_files)
    assert len(modified) == 0
    assert len(added) == 0
    assert len(deleted) == 0
