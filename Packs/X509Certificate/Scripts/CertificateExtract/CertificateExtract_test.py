def load_json_data(path):
    import json

    with open(path, 'r') as f:
        return json.load(f)


def test_pem():
    """
    Given:
        - a string with a certificate in PEM format
    When
        - running certificate_extract_command function
    Then
        - the result of the function should match the one loaded from a specific JSON file
    """
    from CertificateExtract import certificate_extract_command

    with open('test_data/test.pem', 'r') as f:
        contents = f.read()

    context = certificate_extract_command({'pem': contents}).to_context()
    expected_result = load_json_data('test_data/pem_result.json')

    assert context['EntryContext'] == expected_result


def test_load_pem(mocker):
    """
    Given:
        - a file path pointing to a certificate in PEM format
    When
        - running certificate_extract_command function
    Then
        - the result of the function should match the one loaded from a specific JSON file
    """
    mocker.patch('demistomock.getFilePath', return_value={
        "path": 'test_data/pandev.pem',
        "name": 'test'
    })

    from CertificateExtract import certificate_extract_command

    context = certificate_extract_command({'entry_id': 'test'}).to_context()
    expected_result = load_json_data('test_data/pandev_result.json')
    assert context['EntryContext'] == expected_result


def test_load_der(mocker):
    """
    Given:
        - a file path pointing to a certificate in DER format
    When
        - running certificate_extract_command function
    Then
        - the result of the function should match the one loaded from a specific JSON file
    """
    mocker.patch('demistomock.getFilePath', return_value={
        "path": 'test_data/pandev.der',
        "name": 'test'
    })

    from CertificateExtract import certificate_extract_command

    context = certificate_extract_command({'entry_id': 'test'}).to_context()
    expected_result = load_json_data('test_data/pandev_result.json')

    assert context['EntryContext'] == expected_result


def test_load_pem2(mocker):
    """
    Given:
        - a file path pointing to a certificate in PEM format
    When
        - running certificate_extract_command function
    Then
        - the result of the function should match the one loaded from a specific JSON file
    """
    mocker.patch('demistomock.getFilePath', return_value={
        "path": 'test_data/test2.pem',
        "name": 'test'
    })

    from CertificateExtract import certificate_extract_command

    context = certificate_extract_command({'entry_id': 'test'}).to_context()
    expected_result = load_json_data('test_data/test2_result.json')

    assert context['EntryContext'] == expected_result
