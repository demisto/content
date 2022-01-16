import pytest


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
