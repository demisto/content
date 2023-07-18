import demistomock as demisto  # noqa: F401
import pytest


def test_canonicalize():
    from InferWhetherServiceIsDev import _canonicalize_string
    assert _canonicalize_string("BLAH") == "blah"
    assert _canonicalize_string("'BLAH'") == "blah"
    assert _canonicalize_string('" BLAH" ') == "blah"

@pytest.mark.parametrize('tags_raw,matches', [([{"Key": "ENV", "Value": "nprd"}], [{"Key": "ENV", "Value": "nprd"}])])
def test_get_indicators_from_key_value_pairs(tags_raw, matches):
    from InferWhetherServiceIsDev import get_indicators_from_key_value_pairs
    from InferWhetherServiceIsDev import is_dev_indicator
    #_is_dev_indicator = is_dev_indicator('nprd')
    assert get_indicators_from_key_value_pairs(tags_raw, is_dev_indicator) is matches


def test_is_dev_indicator():
    from InferWhetherServiceIsDev import is_dev_indicator
    
    # Test Dev Matches
    assert is_dev_indicator('dev')
    assert is_dev_indicator('uat')
    assert is_dev_indicator('non-prod')
    assert is_dev_indicator('noprod')
    
    #Test no match
    assert not is_dev_indicator('devops')
    assert not is_dev_indicator('prod')
    assert not is_dev_indicator('pr')


def test_is_prod_indicator():
    from InferWhetherServiceIsDev import is_prod_indicator



# def test_is_dev_according_to_classifications():
#     from InferWhetherServiceIsDev import is_dev_according_to_classifications

#     assert is_dev_according_to_classifications(["SshServer", "DevelopmentEnvironment"])
#     assert not is_dev_according_to_classifications(["RdpServer", "SelfSignedCertificate"])


@pytest.mark.parametrize('in_classifications,in_tags,expected_out_boolean',
                         [([], [{"Key": "ENV", "Value": "non-prod", "Source": "AWS"}], [{'result': 'The service is development', 'confidence': 'Likely Development', 'reason': 'Match on tag {ENV: non-prod} from AWS'}])])
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
    expected_calls_to_mock_object = [unittest.mock.call('setAlert', {'asmdevcheckdetails': expected_out_boolean})]
    assert demisto_execution_mock.call_args_list == expected_calls_to_mock_object


                        #   (["DevelopmentEnvironment"], [], True),
                        #   (["DevelopmentEnvironment"], [{"Key": "ENV", "Value": "pprod"}], True),
                        #   ([], [], False),
                        #   # unexpected format and/or missing fields yield False & no errors
                        #   ([], [{"key": "ENV", "value": "dev"}], False),
                        #   (None, [], False),
                        #   ([], None, False),
                        #   (None, None, False)