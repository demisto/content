def test_parse_all_certificates(datadir):
    from CertificatesTroubleshoot import parse_all_certificates
    from pathlib import Path
    from json import load
    certificate = Path(datadir['CA.pem']).read_text()

    assert parse_all_certificates(certificate) == load(Path(datadir['output.json']).open())
