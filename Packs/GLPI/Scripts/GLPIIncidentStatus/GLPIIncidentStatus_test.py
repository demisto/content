"""GLPIIncidentStatus Script for Cortex XSOAR - Unit Tests file"""


from GLPIIncidentStatus import glpi_incident_status


def test_glpi_incident_status():
    result = glpi_incident_status()
    assert result == ('#000000', 'Pending Update')
