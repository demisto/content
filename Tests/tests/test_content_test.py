import pytest
from Tests.test_content import extract_server_numeric_version

DEFAULT_VERSION = '99.99.98'


@pytest.mark.parametrize('name, default_ver, output', [
    ('Demisto-Circle-CI-Content-PreGA-5.5-80316', DEFAULT_VERSION, '5.5.0'),
    ('Demisto-Marketplace-Content-GA_6_0-86106', DEFAULT_VERSION, '6.0.0'),
    ('Demisto-Marketplace-Content-Master-88597', DEFAULT_VERSION, DEFAULT_VERSION)
])
def test_extract_server_numeric_version(name, default_ver, output):
    assert extract_server_numeric_version(name, default_ver) == output
