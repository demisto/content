import json

from pytest_mock import MockerFixture
from CertificatesTroubleshoot import parse_all_certificates, main
from pathlib import Path
import demistomock as demisto


def load_json_file(path):
    with open(path) as json_file:
        return json.load(json_file)


def test_parse_all_certificates(datadir):
    certificate = Path(datadir['CA.pem']).read_text()
    assert parse_all_certificates(certificate) == load_json_file(datadir['output.json'])


def test_openssl(mocker: MockerFixture, datadir):
    process_mock = mocker.MagicMock()
    certificate = Path(datadir['openssl-github-output.txt']).read_text()
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
