from Kafka_V2 import create_certificate
import os


def test_create_certificate():
    ca_cert = 'dummy_cert'
    client_cert = 'dummy_client'
    key = 'dummy_key'
    password = 'dummy_pass'
    res = create_certificate(ca_cert, client_cert, key, password)
    assert res.password == password
    with open(res.certfile, 'rb') as f:
        assert f.read() == client_cert
    os.remove(res.certfile)
    with open(res.cafile, 'rb') as f:
        assert f.read() == ca_cert
    os.remove(res.cafile)
    with open(res.keyfile, 'rb') as f:
        assert f.read() == key
    os.remove(res.keyfile)
