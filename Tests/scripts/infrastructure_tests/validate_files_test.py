from Tests.scripts.validate_files import FilesValidator
# from Tests.scripts.hook_validations.conf_json import ConfJsonValidator


def packagify_mock_no_change(modified, added, removed, tag):
    return modified, added, removed


def test_get_modified_files(mocker):
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

    changed_files = 'R100       Integrations/Recorded_Future_v2/Recorded_Future.py ' \
                    'Integrations/Recorded_Future/Recorded_Future_v2.py'
    modified, added, deleted, old_format = file_validator.get_modified_files(changed_files)
    assert len(modified) == 0
    assert len(added) == 1
    assert 'Integrations/Recorded_Future/Recorded_Future.yml' in added
    assert len(deleted) == 1
    assert 'Integrations/integration-Recorded_Future.yml' in deleted
