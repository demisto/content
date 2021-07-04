import pytest
import rsa

from CommonServerPython import DemistoException
from EncryptionTools import get_public_key, get_private_key, create_keys
import demistomock as demisto


class TestGetPublicKey:
    @staticmethod
    def test_no_data():
        with pytest.raises(DemistoException, match='Public key is not defined.'):
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
        with pytest.raises(DemistoException, match='Private key is not defined.'):
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
    def test_keys_defined_in_params(key_type):
        params = {
            key_type: 'A key',
        }

        with pytest.raises(
            DemistoException,
            match='Public key or Private key are provided in the instance configuration. Skipping new keys creation.',
        ):
            create_keys(params, {})

    @staticmethod
    def test_keys_already_generated_no_override(mocker):
        import EncryptionTools as enc
        mocker.patch.object(enc, 'get_public_key', return_value='key')

        with pytest.raises(
            DemistoException,
            match='Keys have already been generated. You can use the "override_keys=true" argument in order to '
            'override the current generated keys.',
        ):
            create_keys({}, {})

    @staticmethod
    def test_keys_already_generated_override(mocker):
        mocker.patch.object(demisto, 'results')

        create_keys({}, {})

        results = demisto.results.call_args[0]
        assert 'Keys created successfully.' == results[0]
