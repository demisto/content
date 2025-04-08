import pytest
from GetDomainCertificate import SSL_info, main
from unittest.mock import patch, MagicMock


@patch('GetDomainCertificate.ssl.create_default_context')
@patch('GetDomainCertificate.socket.create_connection')
def test_ssl_info_success(mock_create_connection, mock_create_default_context):
    """
    Given:
        - A domain with a valid SSL certificate.
    When:
        - Retrieving SSL certificate information.
    Then:
        - Ensure the certificate information is returned correctly.
    """
    # Mock data
    mock_cert = {
        'subject': ((('countryName', 'US'),), (('organizationName', 'Example Inc'),), (('commonName', 'example.com'),)),
        'issuer': ((('countryName', 'US'),), (('organizationName', 'Example CA'),), (('commonName', 'Example CA Root'),)),
        'notBefore': "Jan 1 00:00:00 2023 GMT",
        'notAfter': "Jan 1 00:00:00 2024 GMT"
    }

    # Mock the SSL context and connection
    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_create_connection.return_value.__enter__.return_value = mock_sock
    mock_create_default_context.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock
    mock_ssock.getpeercert.return_value = mock_cert

    # Expected result
    expected_result = {
        'domain': 'example.com',
        'issuer_country': 'US',
        'issuer_organization': 'Example CA',
        'issuer_common_name': 'Example CA Root',
        'subject_country': 'US',
        'subject_organization': 'Example Inc',
        'issue_date': '2023-01-01T00:00:00',
        'expire_date': '2024-01-01T00:00:00'
    }

    result = SSL_info('example.com')
    assert result == expected_result


def test_SSL_info_error():
    with patch('socket.create_connection', side_effect=ConnectionError):
        result = SSL_info('example.com')
        assert result == {}


@pytest.mark.parametrize('args, expected_outputs', [
    (
        {'domains': 'example.com', 'verbose': 'false'},
        [{
            'domain': 'example.com',
            'issuer_country': 'US',
            'issuer_organization': 'Example Inc',
            'issuer_common_name': 'Example CA',
            'subject_country': 'US',
            'subject_organization': 'Example.com',
            'issue_date': '2023-01-01T00:00:00',
            'expire_date': '2024-01-01T00:00:00',
        }]
    ),
    (
        {'domains': 'example.com,test.com', 'verbose': 'true'},
        [
            {
                'domain': 'example.com',
                'issuer_country': 'US',
                'issuer_organization': 'Example Inc',
                'issuer_common_name': 'Example CA',
                'subject_country': 'US',
                'subject_organization': 'Example.com',
                'issue_date': '2023-01-01T00:00:00',
                'expire_date': '2024-01-01T00:00:00',
                'full_response': {'some': 'data'},
            },
            {
                'domain': 'test.com',
                'issuer_country': 'US',
                'issuer_organization': 'Test Inc',
                'issuer_common_name': 'Test CA',
                'subject_country': 'US',
                'subject_organization': 'Test.com',
                'issue_date': '2023-02-01T00:00:00',
                'expire_date': '2024-02-01T00:00:00',
                'full_response': {'some': 'other_data'},
            }
        ]
    ),
])
def test_main(args, expected_outputs):
    with patch('GetDomainCertificate.demisto.args', return_value=args), \
            patch('GetDomainCertificate.SSL_info') as mock_ssl_info, \
            patch('GetDomainCertificate.return_results') as mock_return_results:

        mock_ssl_info.side_effect = expected_outputs

        main()

        assert mock_return_results.call_count == len(expected_outputs)
        for i, expected_output in enumerate(expected_outputs):
            assert mock_return_results.call_args_list[i][0][0].outputs == expected_output


def test_main_error():
    with patch('GetDomainCertificate.demisto.args', return_value={'domains': 'invalid.com'}), \
            patch('GetDomainCertificate.SSL_info', return_value={}), \
            patch('GetDomainCertificate.return_results') as mock_return_results:

        main()

        mock_return_results.assert_called_once_with(
            "Unable to retrieve SSL certificate information for invalid.com. Please check the domain name or make sure it uses"
            "SSL (HTTPS)."
        )
