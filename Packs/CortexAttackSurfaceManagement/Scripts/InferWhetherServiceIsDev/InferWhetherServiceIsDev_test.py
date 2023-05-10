import demistomock as demisto  # noqa: F401
import pytest


def test_canonicalize():
    from InferWhetherServiceIsDev import _canonicalize_string
    assert _canonicalize_string("BLAH") == "blah"
    assert _canonicalize_string("'BLAH'") == "blah"
    assert _canonicalize_string('" BLAH" ') == "blah"


def test_is_dev_according_to_key_value_pairs():
    from InferWhetherServiceIsDev import is_dev_according_to_key_value_pairs

    # dev indicator with varying keys
    assert is_dev_according_to_key_value_pairs([{"Key": "env", "Value": "dev"},
                                                {"Key": "Name", "Value": "rdp_server"},
                                                {"Key": "test", "Value": ""}])
    assert is_dev_according_to_key_value_pairs([{"Key": "ENVIRONMENT", "Value": "TEST"}])

    # pre-prod counts as dev and not as prod
    assert is_dev_according_to_key_value_pairs([{"Key": "Stage", "Value": "status - preprod"}])

    # no dev indicator
    assert not is_dev_according_to_key_value_pairs([{"Key": "env", "Value": "prod"}])
    assert not is_dev_according_to_key_value_pairs([{"Key": "dev", "Value": "my name"}])

    # conflicting indicators
    assert not is_dev_according_to_key_value_pairs([{"Key": "env", "Value": "prod"},
                                                    {"Key": "env", "Value": "dev"}])

    # extra arguments ok
    assert is_dev_according_to_key_value_pairs([{"Key": "ENVIRONMENT", "Source": "AWS", "Value": "TEST"}])


def test_is_dev_according_to_classifications():
    from InferWhetherServiceIsDev import is_dev_according_to_classifications

    assert is_dev_according_to_classifications(["SshServer", "DevelopmentEnvironment"])
    assert not is_dev_according_to_classifications(["RdpServer", "SelfSignedCertificate"])


@pytest.mark.parametrize('in_classifications,in_tags,expected_out_boolean',
                         [([], [{"Key": "ENV", "Value": "nprd"}], True),
                          (["DevelopmentEnvironment"], [], True),
                          (["DevelopmentEnvironment"], [{"Key": "ENV", "Value": "pprod"}], True),
                          ([], [], False),
                          # unexpected format and/or missing fields yield False & no errors
                          ([], [{"key": "ENV", "value": "dev"}], False),
                          (None, [], False),
                          ([], None, False),
                          (None, None, False)])
def test_main(mocker, in_classifications, in_tags, expected_out_boolean):
    import InferWhetherServiceIsDev
    import unittest

    # Construct payload
    arg_payload = {}
    if in_classifications:
        arg_payload["active_classifications"] = in_classifications
    if in_tags:
        arg_payload["asm_tags"] = in_tags
    mocker.patch.object(demisto,
                        'args',
                        return_value=arg_payload)

    # Execute main using a mock that we can inspect for `executeCommand`
    demisto_execution_mock = mocker.patch.object(demisto, 'executeCommand')
    InferWhetherServiceIsDev.main()

    # Verify the output value was set
    expected_calls_to_mock_object = [unittest.mock.call('setAlert', {'asmdevcheck': expected_out_boolean})]
    assert demisto_execution_mock.call_args_list == expected_calls_to_mock_object
