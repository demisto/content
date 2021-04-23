"""
PingCastle Integration for Cortex XSOAR - Unit Tests file
This file contains the Pytest Tests for the PingCastle Integration

This file tests the get_report command but not the long running integration command because in order to do that
I'd need to mock socket itself.
"""
import CommonServerPython
import demistomock as demisto


def test_get_report_no_report_available():
    from PingCastle import get_report_command
    demisto.setIntegrationContext({})
    result = get_report_command({'delete_report': 'No'})
    assert result == 'No report available'


def test_get_report_delete():
    report = '<example>report</example>'
    from PingCastle import get_report_command
    demisto.setIntegrationContext({'report': report})
    result: CommonServerPython.CommandResults = get_report_command({'delete_report': 'Yes'})
    assert result.raw_response == report
    assert result.outputs == {'report': report}
    assert demisto.getIntegrationContext().get('report') is None


def test_get_report_no_delete():
    report = '<example>report</example>'
    from PingCastle import get_report_command
    demisto.setIntegrationContext({'report': report})
    result: CommonServerPython.CommandResults = get_report_command({'delete_report': 'No'})
    assert result.raw_response == report
    assert result.outputs == {'report': report}
    assert demisto.getIntegrationContext().get('report') is not None
