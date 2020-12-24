"""
Unittests for GetIntegrationParameters
"""
from GetIntegrationParameters import get_conf


class TestGetIntegrationParameters:
    def test_get_conf(self, mocker):
        instance_name = 'integration_instance'
        mocker.patch(
            'GetIntegrationParameters.get_configurations_from_xsoar',
            return_value={
                'instances': [{
                    'name': instance_name,
                    'brand': instance_name
                }],
                'configurations': [{
                    'id': instance_name
                }]
            }
        )
        conf = get_conf(instance_name)
        assert conf == (
            {'id': 'integration_instance'},
            {'name': 'integration_instance', 'brand': 'integration_instance'}
        )
