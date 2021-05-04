import pytest
import rsa

from CommonServerPython import DemistoException
from Encryption import get_public_key, get_private_key, create_keys
import demistomock as demisto


class TestGetPublicKey:
    @staticmethod
    def test_no_data():
        with pytest.raises(DemistoException) as e:
            get_public_key()

    @staticmethod
    def test_get_from_params(mocker):
        mocker.patch.object(demisto, 'params', return_value={
            'public_key': '-----BEGIN RSA PUBLIC KEY-----\nMAoCAwCCbQIDAQAB\n-----END RSA PUBLIC KEY-----\n',
        })

        public_key = get_public_key()

        assert isinstance(public_key, rsa.PublicKey)

    @staticmethod
    def test_get_from_context():
        demisto.setIntegrationContext({
            'public_key': '-----BEGIN RSA PUBLIC KEY-----\nMAoCAwCCbQIDAQAB\n-----END RSA PUBLIC KEY-----\n',
        })

        public_key = get_public_key()

        assert isinstance(public_key, rsa.PublicKey)


class TestGetPrivateKey:
    @staticmethod
    def test_no_data():
        with pytest.raises(DemistoException):
            get_private_key()

    @staticmethod
    def test_get_from_params(mocker):
        mocker.patch.object(demisto, 'params', return_value={
            'private_key': '-----BEGIN RSA PRIVATE KEY-----\nMCICAQACAwCLNwIDAQABAgJ+iQICAOMCAgCdAgFLAgFlAgFr'
                           '\n-----END RSA PRIVATE KEY-----\n',
        })

        private_key = get_private_key()

        assert isinstance(private_key, rsa.PrivateKey)

    @staticmethod
    def test_get_from_context():
        demisto.setIntegrationContext({
            'private_key': '-----BEGIN RSA PRIVATE KEY-----\nMCICAQACAwCLNwIDAQABAgJ+iQICAOMCAgCdAgFLAgFlAgFr'
                           '\n-----END RSA PRIVATE KEY-----\n',
        })

        private_key = get_private_key()

        assert isinstance(private_key, rsa.PrivateKey)


class TestCreateKeys:
    @staticmethod
    @pytest.mark.parametrize('key_type', ['public_key', 'private_key'])
    def keys_defined_in_params(key_type):
        params = {
            key_type: 'A key',
        }

        with pytest.raises(DemistoException):
            create_keys(params, {})
