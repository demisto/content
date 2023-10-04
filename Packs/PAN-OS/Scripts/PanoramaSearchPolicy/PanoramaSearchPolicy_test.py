import demistomock as demisto  # noqa: F401


def test_panorama_search_policy_command(mocker):
    """Tests panorama_search_policy_command command function.

        Given:
            - Mock args and data from !pan-os comands.
        When:
            - Running the 'panorama_search_policy_command' function.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from PanoramaSearchPolicy import panorama_search_policy_command

    def executeCommand(name, args):
        if name == "pan-os-platform-get-device-groups":
            return [{'Contents': [{'name': 'dg_name'}], "Type": 1}]
        elif name == "pan-os-list-rules":
            return [{'Contents': 'Example Rule info', "Type": 1}]
        return None
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {"rule_name": "fake rule name"}
    result = panorama_search_policy_command(args)
    assert result == {'Contents': 'Example Rule info', "Type": 1}
