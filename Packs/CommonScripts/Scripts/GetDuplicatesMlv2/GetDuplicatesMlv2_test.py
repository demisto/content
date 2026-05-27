import demistomock as demisto
from GetDuplicatesMlv2 import main, Utils
from CommonServerPython import entryTypes


def test_main(mocker):
    def executeCommand(name, args=None):
        if name == 'findIndicators':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': [{
                        "investigationIDs": ["1", "2"],
                        "value": "test@test.com",
                        "indicator_type": "Email",
                    }]
                }
            ]
        elif name == 'getIncidents':
            return demisto.exampleIncidents  # use original mock
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={
        "compareIndicators": "Email, IP, Domain, File SHA256, File MD5, URL",
        "compareEmailLabels": "Email/headers/From, Email/headers/Subject, Email/text, Email/html, Email/attachments",
        "UseLocalEnvDuplicatesInLastDays": "30"
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    # validate our mocks are good
    assert 'URL' in demisto.args()['compareIndicators']
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0][0]
    assert results.startswith('Did not find any')


def test_extract_domain_from_url(mocker):
    import requests

    class MySession(requests.Session):
        def merge_environment_settings(self, *args, **kwargs):
            config = super(MySession, self).merge_environment_settings(*args, **kwargs)
            config['verify'] = False
            return config

    mocker.patch('requests.Session', MySession)

    res = Utils.extract_domain_from_url("https://www.google.com")  # disable-secrets-detection
    assert res == 'google.com'
    res = Utils.extract_domain_from_url("https://www.google.co.il")  # disable-secrets-detection
    assert res == 'google.co.il'

def test_safe_pickle_loads_legitimate_data():
    """Verify that a legitimate pickle payload with allowed types loads successfully."""
    import pickle
    from CommonServerPython import safe_pickle_loads
    from GetDuplicatesMlv2 import _ALLOWED_CLASSES, _SAFE_MODULE_PREFIXES

    legitimate_data = {"key": "value", "numbers": [1, 2, 3]}
    payload = pickle.dumps(legitimate_data)
    result = safe_pickle_loads(payload, _ALLOWED_CLASSES, _SAFE_MODULE_PREFIXES)
    assert result == legitimate_data


def test_safe_pickle_loads_blocks_malicious_payload():
    """Verify that a payload trying to execute os.system is blocked.

    The malicious payload may be caught by either Layer 1 (RestrictedUnpickler
    raising pickle.UnpicklingError) or Layer 2 (opcode validator raising
    UnsafePickleError). Both are acceptable -- the key is that it never executes.
    """
    import pickle
    import pytest
    from CommonServerPython import UnsafePickleError, safe_pickle_loads
    from GetDuplicatesMlv2 import _ALLOWED_CLASSES, _SAFE_MODULE_PREFIXES

    # Malicious pickle that would call os.system('echo pwned')
    malicious_pickle = (
        b"\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00"
        b"\x8c\x02os\x8c\x06system\x93\x8c\x0becho pwned\x85R."
    )
    with pytest.raises((UnsafePickleError, pickle.UnpicklingError)):
        safe_pickle_loads(malicious_pickle, _ALLOWED_CLASSES, _SAFE_MODULE_PREFIXES)


def test_validate_pickle_opcodes_blocks_inst():
    """Verify INST opcode is blocked."""
    import pytest
    from CommonServerPython import UnsafePickleError, validate_pickle_opcodes

    # INST opcode is 'i' (0x69) -- protocol 0 class instantiation
    inst_payload = b"(ios\nsystem\nS'echo pwned'\n."
    with pytest.raises(UnsafePickleError, match="INST"):
        validate_pickle_opcodes(inst_payload)


def test_validate_pickle_opcodes_allows_legitimate_opcodes():
    """Verify that a normal pickle payload passes opcode validation without error."""
    import pickle
    from CommonServerPython import validate_pickle_opcodes

    legitimate_data = {"key": "value", "list": [1, 2, 3]}
    payload = pickle.dumps(legitimate_data)
    # Should not raise
    validate_pickle_opcodes(payload)
