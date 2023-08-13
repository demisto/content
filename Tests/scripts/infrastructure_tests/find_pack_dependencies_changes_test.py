import pytest
from Tests.scripts.find_pack_dependencies_changes import compare


@pytest.mark.parametrize('previous, current, expected_diff', [
    (
        {"pack": {"dependencies": "bla", "allLevelDependencies": "bla"}},
        {"pack": {"dependencies": "bla", "allLevelDependencies": "bla"}},
        {},
    ),
    (
        {},
        {"pack": {"dependencies": "bla", "allLevelDependencies": "bla"}},
        {"pack": {"added": {"dependencies": "bla", "allLevelDependencies": "bla"}}},
    ),
    (
        {"pack": {"dependencies": "bla", "allLevelDependencies": "bla"}},
        {},
        {"pack": {"removed": {"dependencies": "bla", "allLevelDependencies": "bla"}}},
    ),
    (
        {"pack": {"dependencies": {"CommonScripts": {"mandatory": True}}, "allLevelDependencies": "bla"}},
        {"pack": {"dependencies": {"CommonScripts": {"mandatory": False}}, "allLevelDependencies": "bla"}},
        {"pack": {"modified": {"dependencies": {"CommonScripts": {"mandatory": False}}}}},
    ),
    (
        {
            "pack": {"dependencies": {}, "allLevelDependencies": "bla"},
            "pack2": {"dependencies": {"CommonScripts": {"mandatory": True}}, "allLevelDependencies": "bla"},
        },
        {
            "pack": {"dependencies": {"CommonScripts": {"mandatory": False}}, "allLevelDependencies": "bla"},
            "pack2": {"dependencies": {"CommonScripts": {"mandatory": False}}, "allLevelDependencies": "bla"},
        },
        {
            "pack": {"added": {"dependencies": {"CommonScripts": {"mandatory": False}}}},
            "pack2": {"modified": {"dependencies": {"CommonScripts": {"mandatory": False}}}},
        },
    ),
])
def test_compare(previous: dict, current: dict, expected_diff: dict):
    assert compare(previous, current) == expected_diff
