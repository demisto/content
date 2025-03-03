import json
import subprocess

from pytest_mock import MockerFixture
from CertificatesTroubleshoot import parse_all_certificates, main, get_certificate_openssl
from pathlib import Path
import demistomock as demisto


def load_json_file(path):
    with open(path) as json_file:
        return json.load(json_file)


def test_parse_all_certificates():
    certificate = Path('test_data/CA.pem').read_text()
    assert parse_all_certificates(certificate) == load_json_file('test_data/output.json')


def test_openssl_timeout(mocker: MockerFixture, datadir):

    process_mock = mocker.MagicMock()
    mocker.patch('subprocess.Popen', return_value=process_mock)
    mocked_return_error = mocker.patch("CertificatesTroubleshoot.return_error", return_value=None)
    mocker.patch.object(demisto, "error")
    process_mock.communicate.side_effect = [subprocess.TimeoutExpired('mock expired command', timeout=60), ('success', None)]

    get_certificate_openssl('api.github.com', 443)
    process_mock.kill.assert_called_once()
    mocked_return_error.assert_called_once_with('openssl command timed out, see logs for more details.')


def test_openssl(mocker: MockerFixture):
    process_mock = mocker.MagicMock()
    certificate = Path('test_data/openssl-github-output.txt').read_text()
    process_mock.communicate.return_value = (certificate, None)

    mocker.patch('subprocess.Popen', return_value=process_mock)
    mocker.patch.object(demisto, 'args', return_value={
        'endpoint': 'api.github.com',
        'port': '443',
        'mode': 'openssl',
    })
    return_outputs_mock = mocker.patch('CertificatesTroubleshoot.return_outputs')
    main()
    assert return_outputs_mock.call_count == 1
    human_readable, outputs, _ = return_outputs_mock.call_args[0]
    assert 'decrypt.paloaltonetworks.com' in human_readable
    assert len(outputs['TroubleShoot']['Endpoint']['SSL/TLS']['Certificates']) == 4
