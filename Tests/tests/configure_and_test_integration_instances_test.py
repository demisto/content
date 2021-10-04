from Tests.configure_and_test_integration_instances import configure_modified_and_new_integrations


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

    mocker.patch('Tests.configure_and_test_integration_instances.configure_integration_instance',
                 side_effect=configure_integration_instance_mocker)
    old_modules_instances, new_modules_instances = configure_modified_and_new_integrations(
        build=mocker.MagicMock(servers=['server1']),
        modified_integrations_to_configure=['old_integration1', 'old_integration2'],
        new_integrations_to_configure=['new_integration1', 'new_integration2'],
        demisto_client=None
    )
    assert not set(old_modules_instances).intersection(new_modules_instances)
