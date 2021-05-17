import pytest
import demistomock as demisto
from CommonServerPython import entryTypes


NORMAL = [
    {
        "Type": entryTypes["note"],
        "HumanReadable": "tha output!",
    }
]

ERROR = [
    {
        "Type": entryTypes["error"],
        "Contents": "",
    }
]


def executeCommand(result=NORMAL, error=False):
    def inner(command, args=None):
        if command == "CyrenThreatInDepthRenderRelated":
            if error:
                return ERROR
            return result

    return inner


def test_cyren_feed_relationship_normal(mocker):
    """
    Given: Normal arg input
    When: Running cyren_feed_relationship command.
    Then: The output is redirected from the inner script and default columns are used
    """
    from CyrenThreatInDepthRelatedWidget import cyren_feed_relationship

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand())
    args = dict(indicator=dict(some="value"))
    result = cyren_feed_relationship(args)

    demisto.executeCommand.assert_any_call("CyrenThreatInDepthRenderRelated", dict(indicator="{\"some\": \"value\"}"))
    assert result.readable_output == "tha output!"


def test_cyren_feed_relationship_no_indicator(mocker):
    """
    Given: Empty args
    When: Running cyren_feed_relationship command.
    Then: An exception is raised
    """
    from CyrenThreatInDepthRelatedWidget import cyren_feed_relationship

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand())
    with pytest.raises(ValueError):
        cyren_feed_relationship(dict())


def test_cyren_feed_relationship_error_response(mocker):
    """
    Given: An error in the inner script
    When: Running cyren_feed_relationship command.
    Then: An exception is raised
    """
    from CyrenThreatInDepthRelatedWidget import cyren_feed_relationship

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(error=True))
    args = dict(indicator=dict(some="value"))

    with pytest.raises(ValueError):
        cyren_feed_relationship(args)
