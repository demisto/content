import pytest

from Packs.CommonScripts.Scripts.ContentPackInstaller.ContentPackInstaller import ContentPackInstaller
from ContentPackInstaller import *


def getContentPackInstaller(mocker):
    mocker.patch("ContentPackInstaller.execute_command", return_value=(True, [{'response':
                                                                                   [{'id': 'SomePack',
                                                                                     'currentVersion': '1.2.3'}]}]))

    installer = ContentPackInstaller('instance_name')
    assert installer.installed_packs == {'SomePack': Version('1.2.3')}
    return installer


def test_get_pack_data_from_marketplace_strip_array(mocker):
    installer = getContentPackInstaller(mocker)
    mocker.patch("ContentPackInstaller.execute_command",
                 return_value=(True, [{'response':
                                           [{'id': 'InstalledPack',
                                             'currentVersion': '1.2.3'}]},
                                      {'something': 'else'}]))
    assert installer.get_pack_data_from_marketplace('InstalledPack') == {
        'response': [{'currentVersion': '1.2.3', 'id': 'InstalledPack'}]}


def test_get_pack_dependencies_from_marketplace_cached(mocker):
    installer = getContentPackInstaller(mocker)
    installer.packs_dependencies = {'SomePack1234::1.2.3': 'somecachedoutput'}
    assert installer.get_pack_dependencies_from_marketplace({'id': 'SomePack1234', 'version': '1.2.3'}) == 'somecachedoutput'


def test_get_pack_dependencies_from_marketplace_not_cached_invalid(mocker):
    installer = getContentPackInstaller(mocker)
    mocker.patch("ContentPackInstaller.execute_command",
                 return_value=(False, [{'response': 'someinvalidresponse'}]))

    assert installer.get_pack_dependencies_from_marketplace({'id': 'SomePack1234', 'version': '1.2.3'}) == {}


def test_get_pack_dependencies_from_marketplace_not_cached_valid(mocker):
    installer = getContentPackInstaller(mocker)
    mocker.patch("ContentPackInstaller.execute_command",
                 return_value=(False, [{'response': {'packs': [{'extras': {'pack': {'dependencies': ['dep1', 'dep2']}}}]}}]))

    # self.packs_dependencies[pack_key] = res.get('response', {}).get('packs', [])[0] \
    #     .get('extras', {}).get('pack', {}).get('dependencies')
    assert installer.get_pack_dependencies_from_marketplace({'id': 'SomePack1234', 'version': '1.2.3'}) == ['dep1', 'dep2']


def test_get_latest_version_for_pack_good_value(mocker):
    installer = getContentPackInstaller(mocker)
    mocker.patch("ContentPackInstaller.execute_command", return_value=(True, [{'response':
                                                                                   {'id': 'SomePack',
                                                                                    'currentVersion': '1.2.3'}}]))
    assert installer.get_latest_version_for_pack('somepack') == '1.2.3'


def test_get_latest_version_for_pack_good_value(mocker):
    installer = getContentPackInstaller(mocker)
    message = 'an error message from executeCommand'
    mocker.patch("ContentPackInstaller.execute_command", return_value=(True, [{'response': message}]))
    with pytest.raises(ValueError) as e:
        installer.get_latest_version_for_pack('somepack')
    assert message in str(e)
