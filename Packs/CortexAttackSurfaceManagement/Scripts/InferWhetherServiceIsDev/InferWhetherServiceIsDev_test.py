import demistomock as demisto  # noqa: F401


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
