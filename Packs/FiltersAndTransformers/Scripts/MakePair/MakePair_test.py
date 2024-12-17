import demistomock as demisto
import MakePair
import json


def equals_object(obj1, obj2) -> bool:
    if type(obj1) is not type(obj2):
        return False
    elif isinstance(obj1, dict):
        for k1, v1 in obj1.items():
            if k1 not in obj2:
                return False
            if not equals_object(v1, obj2[k1]):
                return False
        return not (set(obj1.keys()) ^ set(obj2.keys()))
    elif isinstance(obj1, list):
        # Compare lists (ignore order)
        list2 = list(obj2)
        for i1, v1 in enumerate(obj1):
            for i2, v2 in enumerate(list2):
                if equals_object(v1, v2):
                    list2.pop(i2)
                    break
            else:
                return False
        return not list2
    else:
        return obj1 == obj2


def test_1(mocker):
    with open('./test_data/test-1.json', 'r') as f:
        test_list = json.load(f)

    for case in test_list:
        mocker.patch.object(demisto, 'args', return_value={
            **case['args']
        })
        mocker.patch.object(MakePair, 'return_results')
        MakePair.main()
        assert MakePair.return_results.call_count == 1
        ret = MakePair.return_results.call_args[0][0]
        assert equals_object(ret, case['result'])
