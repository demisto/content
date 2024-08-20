"""
{
    "marketplaces": ["XSIAM"],
    "additional_needed_packs": [
        {"PackOne": "<instance_name>"},
        "PackTwo": None
    ]
}
This is a test for phishing playbook's flow.
"""

import pytest
from demisto_sdk.commands.common.clients import XsiamClient

# Any additional imports your tests require


@pytest.fixture
def server_client(client_obj: XsiamClient | None = None) -> XsiamClient:
    return client_obj if client_obj else XsiamClient


class TestExample:
    @classmethod
    def setup_class(cls):
        """Run once for the class before *all* tests"""
        print("Testing out running in setup!")

    def setup_method(self, method):
        pass
    
    def some_helper_function():
        pass

    def teardown_method(self, method):
        pass
    
    def test_feature_one(self):
        """Test feature one"""
        print("working!")

    def test_feature_two(self):
        """Test feature two"""
        # Test another aspect of your application
        assert False  # replace with actual assertions for your application

    @classmethod
    def teardown_class(cls):
        """Run once for the class after all tests"""
        pass

if __name__ == "__main__":
    pytest.main()
