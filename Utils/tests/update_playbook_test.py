from Utils.update_playbook import update_playbook


def test_hello():
    update_playbook("../../TestData/Phishing_Investigation_-_Generic.yml", None)

    tested = False
    with open("../../TestData/playbook-Phishing_Investigation_-_Generic.yml", "r") as f:
        expected_yml = f.read().encode('utf-8').splitlines()

        with open("playbook-Phishing_Investigation_-_Generic.yml", "r") as f2:
            actual_yml = f2.read().encode('utf-8').splitlines()

            assert expected_yml == actual_yml, "the yml files aren't equal"
            tested = True

    if not tested:
        assert False, "for some reason the test was not reached assert"
