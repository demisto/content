from Tests.configure_and_test_integration_instances import XSOARBuild


class Options:
    def __init__(self, servers):
        self.servers = servers
        self.ami_env = None
        self.username = None
        self.service_account = None
        self.git_sha1 = None
        self.branch = None
        self.build_number = None
        self.is_nightly = None
        self.secret = None
        self.conf = None
        self.user = None
        self.password = None
        self.is_private = None
        self.test_pack_path = None
        self.id_set_path = None
        self.tests_to_run = None
        self.content_root = None
        self.pack_ids_to_install = None


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

    mocker.patch('Tests.configure_and_test_integration_instances.Build.fetch_pack_ids_to_install',
                 return_value=[])
    mocker.patch('Tests.configure_and_test_integration_instances.Build.fetch_tests_list',
                 return_value=[])
    mocker.patch('Tests.configure_and_test_integration_instances.get_json_file',
                 return_value={'tests': '', 'skipped_integrations': '', 'unmockable_integrations': ''})
    mocker.patch('Tests.configure_and_test_integration_instances.map_server_to_port',
                 return_value=[])
    mocker.patch('Tests.configure_and_test_integration_instances.XSOARBuild.get_servers',
                 return_value=({}, ''))
    mocker.patch('Tests.configure_and_test_integration_instances.configure_integration_instance',
                 side_effect=configure_integration_instance_mocker)
    build = XSOARBuild(Options(servers=['server1']))
    build.servers = ['server1']
    old_modules_instances, new_modules_instances = build.configure_modified_and_new_integrations(
        modified_integrations_to_configure=['old_integration1', 'old_integration2'],
        new_integrations_to_configure=['new_integration1', 'new_integration2'],
        demisto_client_=None,
    )
    assert not set(old_modules_instances).intersection(new_modules_instances)
