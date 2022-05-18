from LoadJSON import load_json
import pytest


@pytest.mark.parametrize('inputs, outputs', [
    ('{"a": 1}', {"a": 1}),
    ('{"a": "b	t"}', {'a': 'b	t'})
])
def test_load_json(inputs, outputs):
    assert outputs == load_json({'input': inputs})['Contents']


def test_load_json_failure():
    with pytest.raises(ValueError):
        load_json({'input': 'not json at all'})
