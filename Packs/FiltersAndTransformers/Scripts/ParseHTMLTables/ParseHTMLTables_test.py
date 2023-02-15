import demistomock as demisto
import json
import pytest

INPUTS = [
    ('test_data/test1-in.html', 'test_data/test1-out.json', None, None),
    ('test_data/test2-in.html', 'test_data/test2-out.json', None, None),
    ('test_data/test3-in.html', 'test_data/test3-out.json', None, None),
    ('test_data/test4-in.html', 'test_data/test4-out.json', None, None),
    ('test_data/test5-in.html', 'test_data/test5-out.json', None, None),
    ('test_data/test6-in.html', 'test_data/test6-out.json', None, None),
    ('test_data/test7-in.html', 'test_data/test7-out.json', None, None),
    ('test_data/test8-in.html', 'test_data/test8-out.json', None, None),
    ('test_data/test9-in.html', 'test_data/test9-out.json', None, None),
    ('test_data/test10-in.html', 'test_data/test10-out.json', None, None),
    ('test_data/test11-in.html', 'test_data/test11-out.json', None, None),
    ('test_data/test12-in.html', 'test_data/test12-out.json', None, 'first_row'),
    ('test_data/test13-in.html', 'test_data/test13-out.json', None, 'first_column'),
    ('test_data/test14-in.html', 'test_data/test14-out.json', None, None),
    ('test_data/test15-in.html', 'test_data/test15-out.json', None, None),
    ('test_data/test16-in.html', 'test_data/test16-out.json', None, None),
    ('test_data/test17-in.html', 'test_data/test17-out.json', None, None),
    ('test_data/test18-in.html', 'test_data/test18-out.json', None, None),
]


@pytest.mark.parametrize('in_file, out_file, title, default_header_line', INPUTS)
def test_main(mocker, in_file, out_file, title, default_header_line):
    from ParseHTMLTables import main

    with open(in_file, 'r') as f:
        value = f.read()

    with open(out_file, 'r') as f:
        expected = json.loads(f.read())

    mocker.patch.object(demisto, 'args', return_value={
        'value': value,
        'title': title,
        'default_header_line': default_header_line
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert json.dumps(results) == json.dumps(expected)
