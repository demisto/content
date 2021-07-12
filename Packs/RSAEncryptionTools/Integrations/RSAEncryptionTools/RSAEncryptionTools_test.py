import pytest
import rsa

from CommonServerPython import DemistoException
from RSAEncryptionTools import get_public_key, get_private_key
import demistomock as demisto


class TestGetPublicKey:
    @staticmethod
    def test_no_data():
        with pytest.raises(DemistoException, match='Public key is not defined.'):
            get_public_key()

    @staticmethod
    def test_get_from_params(mocker):
        mocker.patch.object(demisto, 'params', return_value={
            'public_key': '-----BEGIN RSA PUBLIC KEY-----\nMAoCAwCCbQIDAQAB'  # guardrails-disable-line
                          '\n-----END RSA PUBLIC KEY-----\n',  # guardrails-disable-line
        })

        public_key = get_public_key()

        assert isinstance(public_key, rsa.PublicKey)


class TestGetPrivateKey:
    @staticmethod
    def test_no_data():
        with pytest.raises(DemistoException, match='Private key is not defined.'):
            get_private_key()

    @staticmethod
    def test_get_from_params(mocker):
        mocker.patch.object(demisto, 'params', return_value={
            'private_key': '-----BEGIN RSA PRIVATE KEY-----\n' # guardrails-disable-line
                           'MCICAQACAwCLNwIDAQABAgJ+iQICAOMCAgCdAgFLAgFlAgFr'  # guardrails-disable-line
                           '\n-----END RSA PRIVATE KEY-----\n',  # guardrails-disable-line
        })

        private_key = get_private_key()

        assert isinstance(private_key, rsa.PrivateKey)
