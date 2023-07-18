import demistomock as demisto  # noqa: F401
import pytest


def test_canonicalize():
    from InferWhetherServiceIsDev import _canonicalize_string
    assert _canonicalize_string("BLAH") == "blah"
    assert _canonicalize_string("'BLAH'") == "blah"
    assert _canonicalize_string('" BLAH" ') == "blah"


@pytest.mark.parametrize('tags_raw,matches',
                         [([{"Key": "ENV", "Value": "non-prd"}],
                          [{"Key": "ENV", "Value": "non-prd"}]),
                          ([{"Key": "ENV", "Value": "prd"}], []),
                             ([{"Key": "ENV", "Value": "dv"}, {"Key": "stage", "Value": "sbx"}],
                              [{"Key": "ENV", "Value": "dv"}, {"Key": "stage", "Value": "sbx"}])
                          ])
def test_get_indicators_from_key_value_pairs(tags_raw, matches):
    from InferWhetherServiceIsDev import get_indicators_from_key_value_pairs
    from InferWhetherServiceIsDev import is_dev_indicator

    assert get_indicators_from_key_value_pairs(tags_raw, is_dev_indicator) == matches


def test_is_dev_indicator():
    from InferWhetherServiceIsDev import is_dev_indicator

    # Test Dev Matches
    assert is_dev_indicator('dev')
    assert is_dev_indicator('uat')
    assert is_dev_indicator('non-prod')
    assert is_dev_indicator('noprod')

    # Test no match
    assert not is_dev_indicator('devops')
    assert not is_dev_indicator('prod')
    assert not is_dev_indicator('pr')


def test_is_prod_indicator():
    from InferWhetherServiceIsDev import is_prod_indicator

    # Test Dev Matches
    assert is_prod_indicator('pr')
    assert is_prod_indicator('prod')

    # Test no Matches
    assert not is_prod_indicator('non-prod')
    assert not is_prod_indicator('staging')


@pytest.mark.parametrize('classifications, matches', [(["SshServer", "DevelopmentEnvironment"],
                                                       ["DevelopmentEnvironment"]),
                                                      (["SshServer"], [])])
def test_get_indicators_from_external_classification(classifications, matches):
    from InferWhetherServiceIsDev import get_indicators_from_external_classification

    assert get_indicators_from_external_classification(classifications) == matches


@pytest.mark.parametrize('external, internal, reason',
                         [(["DevelopmentEnvironment"], [],
                          "Match on external classification of DevelopmentEnvironment"),
                          (["DevelopmentEnvironment"], [{"Key": "env", "Value": "non-prod", "Source": "AWS"}],
                          "Match on external classification of DevelopmentEnvironment and tag {env: non-prod} from AWS"),
                          ([], [{"Key": "env", "Value": "non-prod", "Source": "AWS"}],
                          "Match on tag {env: non-prod} from AWS"),
                          ([], [{"Key": "env", "Value": "non-prod", "Source": "AWS"},
                                {"Key": "stage", "Value": "sbx", "Source": "GCP"}],
                          "Match on tag {env: non-prod} from AWS and tag {stage: sbx} from GCP")])
def test_determine_reason(external, internal, reason):
    from InferWhetherServiceIsDev import determine_reason

    assert determine_reason(external, internal) == reason


@pytest.mark.parametrize('external, dev, prd, final',
                         [(["DevelopmentEnvironment"], [], [],
                          {"reason": "Match on external classification of DevelopmentEnvironment",
                           "result": True, "confidence": "Likely Development"}),
                          ([], [], [],
                          {"confidence": "Not Enough Information", "reason": "Neither dev nor prod indicators found",
                           "result": False}),
                          ([], [{"Key": "env", "Value": "non-prod", "Source": "AWS"}], [],
                          {"confidence": "Likely Development", "reason": "Match on tag {env: non-prod} from AWS",
                           "result": True}),
                          (["DevelopmentEnvironment"], [{"Key": "env", "Value": "non-prod", "Source": "AWS"}], [],
                          {"confidence": "Likely Development", "result": True, "reason":
                           "Match on external classification of DevelopmentEnvironment and tag {env: non-prod} from AWS"}),
                          (["DevelopmentEnvironment"], [], [{"Key": "env", "Value": "prd", "Source": "AWS"}],
                          {"result": False, "confidence": "Conflicting Information",
                           "reason": "Match on external classification of DevelopmentEnvironment and tag {env: prd} from AWS"}),
                          ([], [], [{"Key": "env", "Value": "prd", "Source": "AWS"}],
                          {"result": False, "confidence": "Likely Production",
                           "reason": "Match on tag {env: prd} from AWS"}),
                          ([], [{"Key": "env", "Value": "dv", "Source": "Tenable.io"}],
                               [{"Key": "env", "Value": "pr", "Source": "AWS"}],
                          {"result": False, "confidence": "Conflicting Information",
                           "reason": "Match on tag {env: dv} from Tenable.io and tag {env: pr} from AWS"})])
def test_final_decision(external, dev, prd, final):
    from InferWhetherServiceIsDev import final_decision

    assert final_decision(external, dev, prd) == final


@pytest.mark.parametrize('in_classifications,in_tags,expected_out_boolean',
                         [([], [{"Key": "ENV", "Value": "non-prod", "Source": "AWS"}],
                           [{'result': 'The service is development', 'confidence': 'Likely Development',
                             'reason': 'Match on tag {ENV: non-prod} from AWS'}])])
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
