import pytest
from CarbonBlackEndpointStandardEventCollector import Client



@pytest.fixture
def client():
    """Given a CarbonBlackEndpointStandardEventCollector client instance"""
    return Client(url='https://test.carbonblack.com', org_key='test_org', credentials={})

def test_prepare_alerts_result(mocker, client):
    pass
