import pytest
from pathlib import Path
from utils import helper
from utils.helper import PlaybookDataLoader


"""Setup methods"""


@pytest.fixture()
def playbook_data_loader():
    base_path = Path(__file__).resolve().parents[4]
    # Assuming the playbook is in the specified path relative to the current file
    playbook_path = base_path / "Playbooks" / "Cortex_ASM_-_Qualys_Enrichment.yml"
    print(playbook_path)
    return PlaybookDataLoader(playbook_path)


"""Test cases"""


def test_expected_playbook_name_and_id(playbook_data_loader: PlaybookDataLoader):
    """Test the name and ID of the playbook.
    This tests should help with validating the correct file is being tested.

    Args:
        playbook_data_loader (PlaybookDataLoader): a data class that can return a dictionary of the yml playbook file.
    """
    full_data = playbook_data_loader.full_playbook_data
    assert full_data.get("name") == "Cortex ASM - Qualys Enrichment"
    assert full_data.get("id") == "Cortex ASM - Qualys Enrichment"


@pytest.mark.parametrize("asm_system_id_type", ["QUALYS-ASSET-ID"])
def test_expected_asmsystemids_all_in_known_set(playbook_data_loader: PlaybookDataLoader, asm_system_id_type: str):
    """This tests should help with testing the existence of necessary values used by downstream applications.

    Args:
        playbook_data_loader (PlaybookDataLoader): a data class that can return a dictionary of the yml playbook file.
        asm_system_id_type (str): a value that should be set to the key of "Type" under
                                  the "asmsystemids" grid field (incidentfield-ASM_-_System_IDs.json).
    """
    tasks_data = playbook_data_loader.playbook_tasks_data
    key_found = helper.was_grid_field_value_found(
        tasks_data, "val1", asm_system_id_type
    )
    assert key_found
