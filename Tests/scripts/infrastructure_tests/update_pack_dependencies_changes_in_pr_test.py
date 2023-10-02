import Tests.scripts.update_pack_dependencies_changes_in_pr as script_module
import pytest


@pytest.mark.parametrize('mandatory_only, expected_summary', [
    pytest.param(
        False,
        (
            "- Pack **3CXDesktopApp_Supply_Chain_Attack** - first-level dependencies:\n"
            "   - The dependency **MajorBreachesInvestigationandResponse** was changed to *optional*.\n"
            "- Pack **3CXDesktopApp_Supply_Chain_Attack** - all-level dependencies:\n"
            "   - Pack **CommonTypes** is no longer a dependency.\n"
            "   - Pack **Cryptocurrency** is no longer a dependency.\n"
            "- Pack **Campaign** (core pack) - first-level dependencies:\n"
            "   - A new *mandatory* dependency **SplunkPy** was added."
        ),
        id="Should return all diff summary",
    ),
    pytest.param(
        True,
        (
            "- Pack **Campaign** (core pack) - first-level dependencies:\n"
            "   - A new *mandatory* dependency **SplunkPy** was added."
        ),
        id="Should return only existing mandatory dependencies",
    ),
])
def test_get_summary(mandatory_only: bool, expected_summary: str) -> None:
    """
    Given: Mock diff data of a single marketplace, and a set of core packs.
    When: Running get_summary() with different values of mandatory_only.
    Then: Ensure summary string is formatted as expected in each case.
    """
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
                        "mandatory": True,
                        "is_test": False
                    }
                }
            }
        }
    }
    assert script_module.get_summary(diff, {"Campaign"}, mandatory_only) == expected_summary


def test_aggregate_summaries(mocker) -> None:
    """
    Given: Mock diff data.
    When: Running aggregate_summaries().
    Then: Ensure aggregated summaries are in the expected structure.
    """
    from pathlib import Path
    mocker.patch.object(Path, "is_file", return_value=True)
    mocker.patch.object(Path, "read_text", return_value="{}")
    mocker.patch.object(script_module, "get_summary", return_value="data\n")
    assert script_module.aggregate_summaries("mock_artifacts_folder") == {
        mp: "data\n" for mp in (script_module.MarketplaceVersions)
    }


@pytest.mark.parametrize('summaries, mandatory_only, expected_str', [
    pytest.param(
        {
            mp: "data"
            for mp in [
                script_module.MarketplaceVersions.XSOAR,
                script_module.MarketplaceVersions.MarketplaceV2,
                script_module.MarketplaceVersions.XPANSE,
            ]
        },
        False,
        f"{script_module.CHANGES_MSG_TITLE}### XSOAR\ndata\n### XSIAM\ndata\n### XPANSE\ndata\n",
        id="Summaries exist for all marketplaces",
    ),
    pytest.param(
        {},
        False,
        script_module.NO_CHANGES_MSG,
        id="No diff",
    ),
    pytest.param(
        {},
        True,
        script_module.NO_MANDATORY_CHANGES_MSG,
        id="No diff - mandatory only",
    ),
])
def test_format_summaries_to_single_comment(
    summaries: dict,
    mandatory_only: bool,
    expected_str: str,
) -> None:
    """
    Given: Different cases of summaries dict.
    When: Running format_summaries_to_single_comment().
    Then: Ensure the returned comment string is as expected.
    """
    assert script_module.format_summaries_to_single_comment(summaries, mandatory_only) == expected_str
