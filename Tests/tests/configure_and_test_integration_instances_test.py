from Tests.configure_and_test_integration_instances import configure_old_and_new_integrations
from munch import Munch

from Tests.test_content import ParallelPrintsManager


def test_configure_old_and_new_integrations(mocker):
    def configure_integration_instance_mocker(integration,
                                              _,
                                              __,
                                              ___):
        return integration

    mocker.patch('Tests.configure_and_test_integration_instances.configure_integration_instance',
                 side_effect=configure_integration_instance_mocker)
    build_mock = Munch(servers=["server1"])
    old_modules_instances, new_modules_instances = configure_old_and_new_integrations(
        build_mock,
        ['old_integration1', 'old_integration2'],
        ['new_integration1', 'new_integration2'],
        None
    )
    assert not set(old_modules_instances).intersection(new_modules_instances)
