from __future__ import print_function
import demistomock as demisto


def test_timestamp_length_equalization(mocker):
    mocker.patch.object(demisto, 'params', return_value={'proxy': 'test', 'url': 'test'})
    from CrowdStrikeFalcon import timestamp_length_equalization

    timestamp_in_millisecond = 1574585006000
    timestamp_in_seconds = 1574585015

    timestamp_in_millisecond_after, timestamp_in_seconds_after = timestamp_length_equalization(timestamp_in_millisecond,
                                                                                               timestamp_in_seconds)

    assert timestamp_in_millisecond_after == 1574585006
    assert timestamp_in_seconds_after == 1574585015

    timestamp_in_seconds_after, timestamp_in_millisecond_after = timestamp_length_equalization(timestamp_in_seconds,
                                                                                               timestamp_in_millisecond)

    assert timestamp_in_millisecond_after == 1574585006
    assert timestamp_in_seconds_after == 1574585015
