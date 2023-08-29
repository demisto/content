import pytest
from utils import helper

"""Setup methods"""


@pytest.fixture()
def playbook_tasks_data():
    playbook_data = helper.load_yaml_file(
        "./Packs/CortexAttackSurfaceManagement/Playbooks/Cortex_ASM_-_Rapid7_Enrichment.yml"
    )
    tasks = playbook_data["tasks"]
    return tasks


@pytest.fixture()
def full_playbook_data():
    playbook_data = helper.load_yaml_file(
        "./Packs/CortexAttackSurfaceManagement/Playbooks/Cortex_ASM_-_Rapid7_Enrichment.yml"
    )
    return playbook_data


"""Test cases"""


def test_expected_playbook_name_and_id(full_playbook_data: dict):
    """Test the name and ID of the playbook.
    This tests should help with validating the correct file is being tested.

    Args:
        full_playbook_data (dict): the full yml playbook file
    """
    assert full_playbook_data.get("name") == "Cortex ASM - Rapid7 Enrichment"
    assert full_playbook_data.get("id") == "Cortex ASM - Rapid7 Enrichment"


@pytest.mark.parametrize(
    "asm_system_id_type",
    ["RAPID7-ASSET-OS", "RAPID7-ASSET-SITE", "RAPID7-ASSET-ID", "RAPID7-ASSET-NAME"],
)
def test_expected_asmsystemids_all_in_known_set(playbook_tasks_data, asm_system_id_type: str):
    """This tests should help with testing the existence of necessary values used by downstream applications.

    Args:
        playbook_tasks_data: a subset of yml playbook file that only includes the tasks data.
        asm_system_id_type (str): a value that should be set to the key of "Type" under
                                  the "asmsystemids" grid field (incidentfield-ASM_-_System_IDs.json).
    """
    key_found = helper.was_grid_field_value_found(
        playbook_tasks_data, "val1", asm_system_id_type
    )
    assert key_found
