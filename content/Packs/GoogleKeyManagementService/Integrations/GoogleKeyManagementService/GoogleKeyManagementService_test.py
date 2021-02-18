from google.cloud import kms


class Client:
    def __init__(self, params):
        self.project = params.get('project')
        self.location = params.get('location')
        self.key_ring = params.get('key_ring')
        self.service_account = params.get('service_account')
        self.role = params.get('role')


MOCK_PARAMS = {
    "insecure": 'false',
    "location": 'global',
    "key_ring": "should_not_appear",
    "project": "project_name",
    'role': "Project-Admin"
}

CLIENT = Client(MOCK_PARAMS)

MOCK_ARGS_FULL = {
    "location": "global",
    "key_ring": "key_ring",
    "crypto_key": "crypto_key",
    "labels": "label1:value1,label2:value2",
    "rotation_period": "7776000",
    "next_rotation_time": None,
    "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
    "protection_level": "SOFTWARE",
    "purpose": None,
    "attestation": None,
    "state": "ENABLED"
}


def test_update_mask_creation():
    from GoogleKeyManagementService import arg_dict_creator
    created_dict = arg_dict_creator(MOCK_ARGS_FULL.get('labels'))
    assert created_dict['label1'] == 'value1'
    assert created_dict['label2'] == 'value2'


def test_args_extract():
    from GoogleKeyManagementService import demisto_args_extract
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(CLIENT, MOCK_ARGS_FULL)
    assert project_id == 'project_name'
    assert location_id == "global"
    assert key_ring_id == "key_ring"
    assert crypto_key_id == "crypto_key"


def test_get_update_mask():
    from GoogleKeyManagementService import get_update_mask
    update_mask = get_update_mask(MOCK_ARGS_FULL)
    assert len(update_mask['paths']) == 5


def test_update_command_body():
    from GoogleKeyManagementService import get_update_command_body, get_update_mask
    update_mask = get_update_mask(MOCK_ARGS_FULL)
    crypto_key = get_update_command_body(args=MOCK_ARGS_FULL, update_mask=update_mask['paths'])
    assert crypto_key['primary']['state'] == kms.CryptoKeyVersion.CryptoKeyVersionState.ENABLED.value
    assert crypto_key['version_template']['protection_level'] == kms.ProtectionLevel.SOFTWARE.value
    assert crypto_key['labels']['label1'] == 'value1'
    assert crypto_key['rotation_period']['seconds'] == 7776000
    val = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION.value
    assert crypto_key['version_template']['algorithm'] == val
