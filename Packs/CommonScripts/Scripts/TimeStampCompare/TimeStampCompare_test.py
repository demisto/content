from TimeStampCompare import compare_times, time_stamp_compare_command, EQUAL, BEFORE, AFTER, DT_STRING, dateparser


def test_compare_times():
    compared_time = dateparser.parse("2020-02-01T00:00:00")
    equal_tested_time = dateparser.parse("2020-02-01T00:00:00")
    before_tested_time = dateparser.parse("2002-02-01T00:00:00")
    after_tested_time = dateparser.parse("2021-02-01T00:00:00")

    assert compare_times(compared_time, equal_tested_time) == EQUAL
    assert compare_times(compared_time, before_tested_time) == AFTER
    assert compare_times(compared_time, after_tested_time) == BEFORE


def test_command():
    args = {
        'tested_time': "01-01-2020 00:00:00",
        'values_to_compare': "2020-02-01T00:00:00,31.12.2019"
    }
    _, results, _ = time_stamp_compare_command(args)

    assert len(results[DT_STRING]) == 2
    assert results[DT_STRING] == [
        {
            "ComparedTime": "2020-02-01T00:00:00",
            "Result": "after",
            "TestedTime": "01-01-2020 00:00:00"
        },
        {
            "ComparedTime": "31.12.2019",
            "Result": "before",
            "TestedTime": "01-01-2020 00:00:00"
        }
    ]
