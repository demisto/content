from CrowdStrikeStreamingPreProcessing import get_host_from_system_incident
import pytest


test_data = [
    (
        {
            'labels': [
                {'type': 'x', 'value': 'not found'},
                {'type': 'y', 'value': 'not found 1'}
            ]
        },
        ''
    ),
    (
        {
            'labels': [
                {'type': 'x', 'value': 'nothing'},
                {'type': 'System', 'value': 'gotta catch em all'},
                {'type': 'System', 'value': 'you bet ya'},
                {'type': 'y', 'value': 'nanana'}
            ]
        },
        'you bet ya'
    )
]


@pytest.mark.parametrize('incident,expected_host', test_data)
def test_get_host_from_incident(incident, expected_host):
    """Test get_host_from_incident function conditions"""
    assert get_host_from_system_incident(incident) == expected_host
