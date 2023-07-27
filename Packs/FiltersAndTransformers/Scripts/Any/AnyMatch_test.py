import pytest
import demistomock as demisto
from AnyMatch import main


@pytest.mark.parametrize('left,right, call_count,result', [
    ("1,2,3", 1, 3, [True, False, False]),
    ("1,2", "25,10", 2, [True, True]),
    (1, "1,2,3", 1, [True]),
    (1, "21", 1, [True]),
    ("5,1,6,9,65,8", "1,6", 6, [False, True, True, False, False, False]),
    ('a', "kfjua", 1, [True]),
    (1, "1", 1, [True]),
    ('A', "bca", 1, [True]),  # case insensitive
    ("a", "ABC", 1, [True]),  # case insensitive
    ("x", "{'alert' {'data': 'x'}}", 1, [True]),
    ("{'a':1},{'b':2}", "{'a':1,'c':2}", 2, [False, False]),     # {'a':1} is not in {'a':1,'c':2}
    ("{'a':1},{'b':2}", "{a:1}", 2, [False, False]),     # {'a':1} is not in {a:1}}
    ("'','", "{'a':1,'c':2}", 2, [False, True]),     # '' is not in {'a':1,'c':2}, ' is in {'a':1,'c':2}
])
def test_main(mocker, left, right, call_count, result):
    mocker.patch.object(demisto, 'args', return_value={'left': left, 'right': right})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == call_count
    for i in range(len(result)):
        results = demisto.results.call_args_list[i][0][0]
        assert results == result[i]
