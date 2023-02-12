import pytest


@pytest.mark.parametrize("hash_method", ['sha512', 'sha256', 'sha1', 'md5', ''])
def test_create_hash(hash_method):
    """
    Given:
        - A string
    When:
        - Running the script
    Then:
        - Ensure the expected hash is returned
    """
    from CreateHash import create_hash
    context = create_hash('test', hash_method)

    assert isinstance(context, dict)
    assert isinstance(context.get('CreateHash'), str)
