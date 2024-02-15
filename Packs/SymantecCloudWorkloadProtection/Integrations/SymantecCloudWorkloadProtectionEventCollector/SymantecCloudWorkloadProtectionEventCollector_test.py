from typing import Any
import pytest
from CommonServerPython import *


@pytest.fixture(autouse=True)
def mock_base_client(mocker):
    class MockBaseClient:
        def __call__(self, *args: Any, **kwds: Any) -> Any:
            pass
    mocker.patch('SymantecCloudWorkloadProtectionEventCollector.BaseClient', side_effect=MockBaseClient())
    return client
