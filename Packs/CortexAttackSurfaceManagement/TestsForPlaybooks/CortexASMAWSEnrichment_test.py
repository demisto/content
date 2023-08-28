import pytest
from utils import helper


"""Setup methods"""


@pytest.fixture()
def playbook_tasks_data():
    playbook_data = helper.load_yaml_file(
        "./Packs/CortexAttackSurfaceManagement/Playbooks/Cortex_ASM_-_AWS_Enrichment.yml"
    )
    tasks = playbook_data["tasks"]
    return tasks


@pytest.fixture()
def full_playbook_data():
    playbook_data = helper.load_yaml_file(
        "./Packs/CortexAttackSurfaceManagement/Playbooks/Cortex_ASM_-_AWS_Enrichment.yml"
    )
    return playbook_data


"""Test cases"""


def test_expected_playbook_name_and_id(full_playbook_data: dict):
    """Test the name and ID of the AWS playbook.
    This tests should help with validating the correct file is being tested.

    Args:
        full_playbook_data (dict): the full yml playbook file
    """
    assert full_playbook_data.get("name") == "Cortex ASM - AWS Enrichment"
    assert full_playbook_data.get("id") == "Cortex ASM - AWS Enrichment"


@pytest.mark.parametrize(
    "asm_system_id_type", ["ASSET-ID", "ASSET-SUBNET-ID", "ASSET-SG", "ASSET-NIC", "ASSET-VIRTUAL-NET"]
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


@pytest.mark.parametrize(
    "grid_field_data",
    [({"gridfield": "asmsystemids", "val1": "ASSET-TYPE", "val2": "AWS EC2"}),
     ({"gridfield": "asmsystemids", "val1": "ASSET-TYPE", "val2": "AWS S3"})]
)
def test_each_asmsystemid_maps_to_known_asset_type(playbook_tasks_data, grid_field_data: dict):
    """This tests should help with testing the existence of necessary values for ASSET-TYPE used by downstream applications.

    Args:
        playbook_tasks_data: a subset of yml playbook file that only includes the tasks data.
        grid_field_data (dict): a set of values that should be set to the key of "Type" AND "ID" under
                                  the "asmsystemids" grid field (incidentfield-ASM_-_System_IDs.json).
                                  It includes checking that the task is also setting "asmsystemids"
    """
    data_found = helper.check_multiple_grid_field_values(
        playbook_tasks_data, grid_field_data
    )
    assert data_found
