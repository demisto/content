import pytest
from Tests.test_content import extract_server_numeric_version

DEFAULT_VERSION = '99.99.98'


@pytest.mark.parametrize('name, default_ver, output', [
    ('Demisto-Circle-CI-Content-AMI-PreGA-5.5-80316', DEFAULT_VERSION, '5.5.0'),
    ('Demisto-Marketplace-Content-AMI-GA_6_0-86106', DEFAULT_VERSION, '6.0.0'),
    ('Demisto-Marketplace-Content-AMI-Master-88597', DEFAULT_VERSION, DEFAULT_VERSION)
])
def test_extract_server_numeric_version(name, default_ver, output):
    """
    Given
    - An ami instance name, a server default version.
    When
    - Extracting the server version.
    Then
    - Ensure that the server version extracted from 5.5 AMI signature - `Demisto-Circle-CI-Content-PreGA-5.5-80316`
    is 5.5.0.
    - Ensure that the server version extracted from 6.0 AMI signature - `Demisto-Circle-CI-Content-GA_6_0-86106`
    is 6.0.0.
    - Ensure that the server version extracted from master AMI signature - `Demisto-Circle-CI-Content-PreGA-5.5-80316`
    is 99.99.98.
    """
    assert extract_server_numeric_version(name, default_ver) == output
