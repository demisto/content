from pytest_mock import MockerFixture
from CertificatesTroubleshoot import parse_all_certificates, main
from pathlib import Path
from json import load
import demistomock as demisto


def test_parse_all_certificates(datadir):
    certificate = Path(datadir['CA.pem']).read_text()
    assert parse_all_certificates(certificate) == load(Path(datadir['output.json']).open())


def test_openssl(mocker: MockerFixture, datadir):
    mocker.patch('subprocess.check_output', return_value=Path(datadir['openssl-github-output.txt']).read_text())
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
