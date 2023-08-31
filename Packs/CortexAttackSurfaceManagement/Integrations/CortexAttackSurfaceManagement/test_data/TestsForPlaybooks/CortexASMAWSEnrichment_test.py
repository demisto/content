import pytest
from pathlib import Path
from utils import helper
from utils.helper import PlaybookDataLoader


"""Setup methods"""


@pytest.fixture()
def playbook_data_loader():
    base_path = Path(__file__).resolve().parents[4]
    # Assuming the playbook is in the specified path relative to the current file
    playbook_path = base_path / "Playbooks" / "Cortex_ASM_-_AWS_Enrichment.yml"
    print(playbook_path)
    return PlaybookDataLoader(playbook_path)


"""Test cases"""


def test_expected_playbook_name_and_id(playbook_data_loader: PlaybookDataLoader):
    """Test the name and ID of the AWS playbook.
    This tests should help with validating the correct file is being tested.

    Args:
        playbook_data_loader (PlaybookDataLoader): a data class that can return a dictionary of the yml playbook file.
    """
    full_data = playbook_data_loader.full_playbook_data
    assert full_data.get("name") == "Cortex ASM - AWS Enrichment"
    assert full_data.get("id") == "Cortex ASM - AWS Enrichment"


@pytest.mark.parametrize(
    "asm_system_id_type", ["ASSET-ID", "ASSET-SUBNET-ID", "ASSET-SG", "ASSET-NIC", "ASSET-VIRTUAL-NET"]
)
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


@pytest.mark.parametrize(
    "grid_field_data",
    [({"gridfield": "asmsystemids", "val1": "ASSET-TYPE", "val2": "AWS EC2"}),
     ({"gridfield": "asmsystemids", "val1": "ASSET-TYPE", "val2": "AWS S3"})]
)
def test_each_asmsystemid_maps_to_known_asset_type(playbook_data_loader: PlaybookDataLoader, grid_field_data: dict):
    """This tests should help with testing the existence of necessary values for ASSET-TYPE used by downstream applications.

    Args:
       playbook_data_loader (PlaybookDataLoader): a data class that can return a dictionary of the yml playbook file.
        grid_field_data (dict): a set of values that should be set to the key of "Type" AND "ID" under
                                  the "asmsystemids" grid field (incidentfield-ASM_-_System_IDs.json).
                                  It includes checking that the task is also setting "asmsystemids"
    """
    tasks_data = playbook_data_loader.playbook_tasks_data
    data_found = helper.check_multiple_grid_field_values(
        tasks_data, grid_field_data
    )
    assert data_found
