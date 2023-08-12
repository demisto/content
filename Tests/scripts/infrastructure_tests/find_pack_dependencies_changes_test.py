import pytest
from Tests.scripts.find_pack_dependencies_changes import (
    compare,
    get_summary,
)


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


def test_get_summary() -> None:
    diff = {
        "3CXDesktopApp_Supply_Chain_Attack": {
            "modified": {
                "dependencies": {
                    "MajorBreachesInvestigationandResponse": {
                        "display_name": "Rapid Breach Response",
                        "mandatory": False,
                        "is_test": False
                    }
                }
            },
            "removed": {
                "allLevelDependencies": {
                    "CommonTypes": {
                        "display_name": "Common Types",
                        "mandatory": True,
                        "author": "Cortex XSOAR"
                    },
                    "Cryptocurrency": {
                        "display_name": "Cryptocurrency",
                        "mandatory": True,
                        "author": "Cortex XSOAR"
                    },
                }
            }
        },
        "Campaign": {
            "added": {
                "dependencies": {
                    "SplunkPy": {
                        "display_name": "Splunk",
                        "mandatory": False,
                        "is_test": False
                    }
                }
            }
        }
    }
    assert get_summary(diff) == (
        "### This pull request introduces changes in packs dependencies.\n"
        "- In the first-level dependencies of pack 3CXDesktopApp_Supply_Chain_Attack:\n"
        "   - The dependency MajorBreachesInvestigationandResponse was changed from mandatory to optional.\n"
        "- In the all-level dependencies of pack 3CXDesktopApp_Supply_Chain_Attack:\n"
        "   - The mandatory dependency CommonTypes is no longer a dependency.\n"
        "   - The mandatory dependency Cryptocurrency is no longer a dependency.\n"
        "- In the first-level dependencies of pack Campaign:\n"
        "   - A new optional dependency SplunkPy was added.\n"
    )
