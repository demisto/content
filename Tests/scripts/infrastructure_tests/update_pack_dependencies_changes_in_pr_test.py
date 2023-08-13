import Tests.scripts.update_pack_dependencies_changes_in_pr as script_module
import pytest

def test_get_summary() -> None:
    """
    Given: Mock diff data of a single marketplace.
    When: Running get_summary().
    Then: Ensure summary string is formatted as expected.
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
                        "mandatory": False,
                        "is_test": False
                    }
                }
            }
        }
    }
    assert script_module.get_summary(diff) == (
        "- In the first-level dependencies of pack **3CXDesktopApp_Supply_Chain_Attack**:\n"
        "   - The dependency **MajorBreachesInvestigationandResponse** was changed from *mandatory* to *optional*.\n"
        "- In the all-level dependencies of pack **3CXDesktopApp_Supply_Chain_Attack**:\n"
        "   - The *mandatory* dependency **CommonTypes** is no longer a dependency.\n"
        "   - The *mandatory* dependency **Cryptocurrency** is no longer a dependency.\n"
        "- In the first-level dependencies of pack **Campaign**:\n"
        "   - A new *optional* dependency **SplunkPy** was added.\n"
    )


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


@pytest.mark.parametrize('summaries, expected_str', [
    pytest.param(
        {mp: "data" for mp in (script_module.MarketplaceVersions)},
        f"{script_module.CHANGES_MSG_TITLE}### XSOAR\ndata\n### XSIAM\ndata\n### XPANSE\ndata\n",
        id="Summaries exist for all marketplaces",
    ),
    pytest.param(
        {},
        script_module.NO_CHANGES_MSG,
        id="No diff",
    ),
])
def test_format_summaries_to_single_comment(summaries, expected_str) -> None:
    """
    Given: Different cases of summaries dict.
    When: Running format_summaries_to_single_comment().
    Then: Ensure the returned comment string is as expected.
    """
    assert script_module.format_summaries_to_single_comment(summaries) == expected_str
