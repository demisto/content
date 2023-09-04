import demistomock as demisto  # noqa: F401
import pytest


def test_canonicalize():
    from InferWhetherServiceIsDev import _canonicalize_string
    assert _canonicalize_string("BLAH") == "blah"
    assert _canonicalize_string("'BLAH'") == "blah"
    assert _canonicalize_string('" BLAH" ') == "blah"


@pytest.mark.parametrize('tags_raw,matches',
                         [([{"key": "ENV", "value": "non-prd"}],
                          [{"key": "ENV", "value": "non-prd"}]),
                          ([{"key": "ENV", "value": "prd"}], []),
                             ([{"key": "ENV", "value": "dv"}, {"key": "stage", "value": "sbx"}],
                              [{"key": "ENV", "value": "dv"}, {"key": "stage", "value": "sbx"}])
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
                          "match on external classification of DevelopmentEnvironment"),
                          (["DevelopmentEnvironment"], [{"key": "env", "value": "non-prod", "source": "AWS"}],
                          "match on external classification of DevelopmentEnvironment and tag {env: non-prod} from AWS"),
                          ([], [{"key": "env", "value": "non-prod", "source": "AWS"}],
                          "match on tag {env: non-prod} from AWS"),
                          ([], [{"key": "env", "value": "non-prod", "source": "AWS"},
                                {"key": "stage", "value": "sbx", "source": "GCP"}],
                          "match on tag {env: non-prod} from AWS and tag {stage: sbx} from GCP")])
def test_determine_reason(external, internal, reason):
    from InferWhetherServiceIsDev import determine_reason

    assert determine_reason(external, internal) == reason


def test_full_truth_table():
    sample_dev_tag = [{"key": "stage", "value": "non-prod", "source": "AWS"}]
    sample_prod_tag = [{"key": "tier", "value": "prod", "source": "Tenable.io"}]
    # Blank list means no external classification or tag matches.
    sample_no_match = []
    sample_dev_classification = ["DevelopmentEnvironment"]

    from InferWhetherServiceIsDev import final_decision

    # dev == True, all else is False

    # kv pair contains no indicators
    # DevEnv is set (--> dev)
    assert final_decision(sample_dev_classification, sample_no_match, sample_no_match)["result"]
    # DevEnv is not set (--> can't tell)
    assert not final_decision(sample_no_match, sample_no_match, sample_no_match)["result"]

    # kv pair contains dev indicators only
    # DevEnv is set (--> dev)
    assert final_decision(sample_dev_classification, sample_dev_tag, sample_no_match)["result"]
    # DevEnv is not set (--> dev)
    assert final_decision(sample_no_match, sample_dev_tag, sample_no_match)["result"]

    # kv pair contains prod indicators only
    # DevEnv is set (--> conflicting)
    assert not final_decision(sample_dev_classification, sample_no_match, sample_prod_tag)["result"]
    # DevEnv is not set (--> prod)
    assert not final_decision(sample_no_match, sample_no_match, sample_prod_tag)["result"]

    # kv pair contains conflicting indicators
    # DevEnv is set (--> conflicting)
    assert not final_decision(sample_dev_classification, sample_dev_tag, sample_prod_tag)["result"]
    # DevEnv is not set (--> conflicting)
    assert not final_decision(sample_no_match, sample_dev_tag, sample_prod_tag)["result"]


@pytest.mark.parametrize('in_classifications,in_tags,expected_out_boolean',
                         [([], [{"key": "ENV", "value": "non-prod", "source": "AWS"}],
                           [{'result': True, 'result_readable': 'The service is development', 'confidence': 'Likely Development',
                             'reason': 'match on tag {ENV: non-prod} from AWS'}])])
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
