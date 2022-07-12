import pytest
from unittest.mock import mock_open

from Tests.configure_and_test_integration_instances import XSOARBuild, create_build_object, \
    options_handler, XSIAMBuild, get_turned_non_hidden_packs, update_integration_lists, \
    get_packs_with_higher_min_version

XSIAM_SERVERS = {
    "qa2-test-111111": {
        "ui_url": "https://xsiam1.paloaltonetworks.com/",
        "instance_name": "qa2-test-111111",
        "api_key": "1234567890",
        "x-xdr-auth-id": 1,
        "base_url": "https://api1.paloaltonetworks.com/",
        "xsiam_version": "3.2.0",
        "demisto_version": "99.99.98"
    },
    "qa2-test-222222": {
        "ui_url": "https://xsoar-content-2.xdr-qa2-uat.us.paloaltonetworks.com/",
        "instance_name": "qa2-test-222222",
        "api_key": "1234567890",
        "x-xdr-auth-id": 1,
        "base_url": "https://api-xsoar-content-2.xdr-qa2-uat.us.paloaltonetworks.com",
        "xsiam_version": "3.2.0",
        "demisto_version": "99.99.98"
    }
}


def create_build_object_with_mock(mocker, build_object_type):
    args = ['-u', "$USERNAME", '-p', "$PASSWORD", '-c', "$CONF_PATH", '-s', "$SECRET_CONF_PATH",
            '--tests_to_run', "$ARTIFACTS_FOLDER/filter_file.txt",
            '--pack_ids_to_install', "$ARTIFACTS_FOLDER/content_packs_to_install.txt",
            '-g', "$GIT_SHA1", '--ami_env', "$1", '-n', 'false', '--branch', "$CI_COMMIT_BRANCH",
            '--build-number', "$CI_PIPELINE_ID", '-sa', "$GCS_MARKET_KEY", '--build_object_type', build_object_type,
            '--xsiam_machine', "qa2-test-111111", '--xsiam_servers_path', '$XSIAM_SERVERS_PATH']
    options = options_handler(args=args)
    json_data = {
        'tests': [],
        'skipped_integrations': [],
        'unmockable_integrations': [],
    }
    json_data.update(**XSIAM_SERVERS)
    mocker.patch('Tests.configure_and_test_integration_instances.get_json_file',
                 return_value=json_data)
    mocker.patch('Tests.configure_and_test_integration_instances.Build.fetch_tests_list',
                 return_value=[])
    mocker.patch('Tests.configure_and_test_integration_instances.Build.fetch_pack_ids_to_install',
                 return_value=[])
    mocker.patch('Tests.configure_and_test_integration_instances.options_handler',
                 return_value=options)
    mocker.patch('Tests.configure_and_test_integration_instances.XSOARBuild.get_servers',
                 return_value=({'1.1.1.1': '7000'}, '6.5.0'))
    build = create_build_object()
    return build


def test_configure_old_and_new_integrations(mocker):
    """
    Given:
        - A list of new integration that should be configured
        - A list of old integrations that should be configured
    When:
        - Running 'configure_old_and_new_integrations' method on those integrations

    Then:
        - Assert there the configured old integrations has no intersection with the configured new integrations
    """
    def configure_integration_instance_mocker(integration,
                                              _,
                                              __):
        return integration

    mocker.patch('Tests.configure_and_test_integration_instances.XSOARBuild.__init__',
                 return_value=None)

    mocker.patch('Tests.configure_and_test_integration_instances.configure_integration_instance',
                 side_effect=configure_integration_instance_mocker)
    build = XSOARBuild({})
    build.servers = ['server1']
    old_modules_instances, new_modules_instances = build.configure_modified_and_new_integrations(
        modified_integrations_to_configure=['old_integration1', 'old_integration2'],
        new_integrations_to_configure=['new_integration1', 'new_integration2'],
        demisto_client_=None,
    )
    assert not set(old_modules_instances).intersection(new_modules_instances)


@pytest.mark.parametrize('expected_class, build_object_type', [(XSOARBuild, 'XSOAR'), (XSIAMBuild, 'XSIAM')])
def test_create_build(mocker, expected_class, build_object_type):
    """
    Given:
        - server_type of the server we run the build on: XSIAM or XSOAR.
    When:
        - Running 'configure_an_test_integration_instances' script and creating Build object
    Then:
        - Assert there the rigth Build object created: XSIAMBuild or XSOARBuild.
    """
    build = create_build_object_with_mock(mocker, build_object_type)
    assert isinstance(build, expected_class)


NON_HIDDEN_PACKS = [
    ("""
   "tags": [],
+  "hidden": false,
   "marketplaces": [
     "xsoar",
     "marketplacev2""", True),
    ("""
   "tags": [],
+  "hidden": true,
   "marketplaces": [
     "xsoar",
     "marketplacev2""", False),
    ("""
   "tags": [],
   "marketplaces": [
     "xsoar",
     "marketplacev2""", False),
    ("""
    "tags": [],
    +  "hidden": true,
    -  "hidden": false,
    "marketplaces": [
      "xsoar",
      "marketplacev2""", False)
]


@pytest.mark.parametrize('diff, the_expected_result', NON_HIDDEN_PACKS)
def test_get_turned_non_hidden_packs(mocker, diff, the_expected_result):
    """
    Given:
        - A pack_metadata.json content returned from the git diff.
    When:
        - Running 'get_turned_non_hidden_packs' method.
    Then:
        - Assert the expected result is returned.
    """
    build = create_build_object_with_mock(mocker, 'XSOAR')
    mocker.patch('Tests.configure_and_test_integration_instances.run_git_diff', return_value=diff)
    turned_non_hidden = get_turned_non_hidden_packs({'test'}, build)
    assert ('test' in turned_non_hidden) is the_expected_result


UPDATE_INTEGRATION_LISTS = [
    (['test1'], ['test2'], ['test2'], lambda new, modified: 'test2' in new and not modified),
    (['test1'], ['test1'], ['test2'], lambda new, modified: 'test2' not in new and 'test2' in modified),
    (['test1'], [], ['test2'], lambda new, modified: 'test2' not in new and 'test2' in modified),
    (['test1'], ['test1'], ['test1'], lambda new, modified: len(new) == 1 and not modified)
]


@pytest.mark.parametrize(
    'new_integrations_names, turned_non_hidden_packs_id, modified_integrations_names, the_expected_result',
    UPDATE_INTEGRATION_LISTS)
def test_update_integration_lists(mocker, new_integrations_names, turned_non_hidden_packs_id,
                                  modified_integrations_names, the_expected_result):
    """
    Given:
        - New integrations names, modifeid integrations names and turned non-hidden packs ids.
    When:
        - Running 'update_integration_lists' method.
    Then:
        - Assert the turned non-hidden integrations removed from the modified integrations list and
         added to the new integration list.
    """
    mocker.patch('Tests.configure_and_test_integration_instances.packs_names_to_integrations_names',
                 return_value=turned_non_hidden_packs_id)
    returned_results = update_integration_lists(new_integrations_names, set(), modified_integrations_names)
    assert the_expected_result(returned_results[0], returned_results[1])


def test_get_packs_with_higher_min_version(mocker):
    """
    Given:
        - Pack names to install.
    When:
        - Running 'get_packs_with_higher_min_version' method.
    Then:
        - Assert the returned packs are with higher min version than the server version.
    """

    mocker.patch("builtins.open", mock_open(read_data='{"serverMinVersion": "6.6.0"}'))

    packs_with_higher_min_version = get_packs_with_higher_min_version({'TestPack'}, 'content', '6.5.0')
    assert packs_with_higher_min_version == {'TestPack'}
