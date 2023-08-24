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


def test_playbook_name_and_id(full_playbook_data):
    assert full_playbook_data.get("name") == "Cortex ASM - AWS Enrichment"
    assert full_playbook_data.get("id") == "Cortex ASM - AWS Enrichment"


@pytest.mark.parametrize(
    "asm_system_id_types", ["ASSET-ID", "ASSET-SUBNET-ID", "ASSET-SG", "ASSET-NIC", "ASSET-VIRTUAL-NET"]
)
def test_presence_of_asmsystemids(playbook_tasks_data, asm_system_id_types):
    key_found = helper.was_grid_field_value_found(
        playbook_tasks_data, "val1", asm_system_id_types
    )
    assert key_found


@pytest.mark.parametrize(
    "grid_field_data",
    [({"gridfield": "asmsystemids", "val1": "ASSET-TYPE", "val2": "AWS EC2"}),
     ({"gridfield": "asmsystemids", "val1": "ASSET-TYPE", "val2": "AWS S3"})]
)
def test_asset_type_of_asmsytemid(playbook_tasks_data, grid_field_data):
    data_found = helper.check_multiple_grid_field_values(
        playbook_tasks_data, grid_field_data
    )
    assert data_found
