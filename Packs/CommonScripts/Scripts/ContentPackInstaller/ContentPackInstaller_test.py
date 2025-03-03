import pytest

from Packs.CommonScripts.Scripts.ContentPackInstaller.ContentPackInstaller import ContentPackInstaller
from ContentPackInstaller import *


def get_content_pack_installer(mocker):
    mocker.patch("ContentPackInstaller.execute_command", return_value=(True, [{'response':
                                                                               [{'id': 'SomePack',
                                                                                 'currentVersion': '1.2.3'}]}]))

    installer = ContentPackInstaller('instance_name')
    assert installer.installed_packs == {'SomePack': Version('1.2.3')}
    return installer


def test_get_pack_data_from_marketplace_strip_array(mocker):
    """
        Given: an array response from execute command
        When: calling get_pack_data_from_marketplace
        Then: the first response of the array is used
    """
    installer = get_content_pack_installer(mocker)
    mocker.patch("ContentPackInstaller.execute_command",
                 return_value=(True, [{'response':
                                       [{'id': 'InstalledPack',
                                         'currentVersion': '1.2.3'}]},
                                      {'something': 'else'}]))
    assert installer.get_pack_data_from_marketplace('InstalledPack') == {
        'response': [{'currentVersion': '1.2.3', 'id': 'InstalledPack'}]}


def test_get_pack_dependencies_from_marketplace_cached(mocker):
    """
        Given: a cache in place from the marketplace
        When: calling get_pack_dependencies_from_marketplace
        Then: the cache is used
    """
    installer = get_content_pack_installer(mocker)
    installer.packs_dependencies = {'SomePack::1.2.3': 'somecachedoutput'}
    assert installer.get_pack_dependencies_from_marketplace({'id': 'SomePack', 'version': '1.2.3'}) == 'somecachedoutput'


def test_get_pack_dependencies_from_marketplace_not_cached_invalid(mocker):
    """
        Given: no cache
        When: calling get_pack_dependencies_from_marketplace with an invalid response
        Then: an empty dict is returned
    """
    installer = get_content_pack_installer(mocker)
    mocker.patch("ContentPackInstaller.execute_command",
                 return_value=(False, [{'response': 'someinvalidresponse'}]))

    assert installer.get_pack_dependencies_from_marketplace({'id': 'SomePack1234', 'version': '1.2.3'}) == {}


def test_get_pack_dependencies_from_marketplace_not_cached_valid(mocker):
    """
        Given: no cache
        When: calling get_pack_dependencies_from_marketplace with a response
        Then: the dependencies are returned in proper format
    """
    installer = get_content_pack_installer(mocker)
    mocker.patch("ContentPackInstaller.execute_command",
                 return_value=(False, [{'response': {'packs': [{'extras': {'pack': {'dependencies': ['dep1', 'dep2']}}}]}}]))

    # self.packs_dependencies[pack_key] = res.get('response', {}).get('packs', [])[0] \
    #     .get('extras', {}).get('pack', {}).get('dependencies')
    assert installer.get_pack_dependencies_from_marketplace({'id': 'SomePack1234', 'version': '1.2.3'}) == ['dep1', 'dep2']


def test_get_latest_version_for_pack_good_value(mocker):
    """
        Given: a good response from execute_command
        When: calling get_latest_version_for_pack
        Then: the version is returned properly
    """
    installer = get_content_pack_installer(mocker)
    mocker.patch("ContentPackInstaller.execute_command", return_value=(True, [{'response':
                                                                               {'id': 'SomePack',
                                                                                'currentVersion': '1.2.3'}}]))
    assert installer.get_latest_version_for_pack('somepack') == '1.2.3'


def test_get_latest_version_for_pack_bad_value(mocker):
    """
        Given: an error message response from execute_command
        When: calling get_latest_version_for_pack
        Then: a ValueError is raised with the error message from execute_command included
    """
    installer = get_content_pack_installer(mocker)
    message = 'an error message from executeCommand'
    mocker.patch("ContentPackInstaller.execute_command", return_value=(True, [{'response': message}]))
    with pytest.raises(ValueError) as e:
        installer.get_latest_version_for_pack('somepack')
    assert message in str(e)


def test_main(mocker):
    """
        Given: a request to install no packs
        When: calling main
        Then: a response is returned
    """
    mocker.patch.object(demisto, 'args', return_value={'packs_data': [], "pack_version_key": "packversion"})
    mocker.patch("ContentPackInstaller.execute_command",
                 return_value=(False, [{'response': {'packs': [{'extras': {'pack': {'dependencies': ['dep1', 'dep2']}}}]}}]))
    return_results_mock = mocker.patch('ContentPackInstaller.ContentPackInstaller')

    main()
    assert return_results_mock.is_called()


def test_create_context(mocker):
    """
        Given: packs to install output
        When: calling create_context
        Then: the context is created in the proper format
    """
    installer = get_content_pack_installer(mocker)

    packs_to_install = [{'id': 'Pack1', 'version': '1.2.4'}, {'id': 'Pack2', 'version': '1.2.3'}]

    installer.install_packs(packs_to_install)

    context = create_context(packs_to_install, installer)
    assert context == [{'installationstatus': 'Success.', 'packid': 'Pack1', 'packversion': '1.2.4'},
                       {'installationstatus': 'Success.', 'packid': 'Pack2', 'packversion': '1.2.3'}]


def test_is_pack_already_installed(mocker):
    """
        Given: a pock with a version
        When: calling is_pack_already_installed
        Then: results are true if pack with proper version is called
    """
    installer = get_content_pack_installer(mocker)
    assert not installer.is_pack_already_installed({'id': 'ShouldntBeInstalled', 'version': '1.2.3'})
    assert not installer.is_pack_already_installed({'id': 'SomePack', 'version': '1.2.4'})
    assert installer.is_pack_already_installed({'id': 'SomePack', 'version': '1.2.3'})


def test_get_packs_data_for_installation(mocker):
    """
        Given: a request to install pack with 1.2.3 and available version 1.2.4
        When: calling get_packs_data_for_installation
        Then: return 1.2.4
    """
    installer = get_content_pack_installer(mocker)
    mocker.patch("ContentPackInstaller.execute_command", return_value=(True, [{'response':
                                                                               {'id': 'SomePack',
                                                                                'currentVersion': '1.2.4'}}]))
    packs = installer.get_packs_data_for_installation([{'id': 'SomePack', 'version': '1.2.3'}])
    assert packs == [{'id': 'SomePack', 'version': '1.2.4'}]
