import pytest
from utils import helper

"""Setup methods"""


@pytest.fixture()
def playbook_tasks_data():
    print("Playbook YAML file load")
    playbook_data = helper.load_yaml_file(
        "./Packs/CortexAttackSurfaceManagement/Playbooks/Cortex_ASM_-_ServiceNow_CMDB_Enrichment.yml"
    )
    tasks = playbook_data["tasks"]
    return tasks


@pytest.fixture()
def full_playbook_data():
    print("Playbook YAML file load")
    playbook_data = helper.load_yaml_file(
        "./Packs/CortexAttackSurfaceManagement/Playbooks/Cortex_ASM_-_ServiceNow_CMDB_Enrichment.yml"
    )
    return playbook_data


"""Test cases"""


def test_playbook_name_and_id(full_playbook_data):
    assert full_playbook_data.get("name") == "Cortex ASM - ServiceNow CMDB Enrichment"
    assert full_playbook_data.get("id") == "Cortex ASM - ServiceNow CMDB Enrichment"


@pytest.mark.parametrize(
    "asm_system_id_types",
    ["SNOW-CMDB-NIC", "SNOW-CMDB-Parent", "SNOW-CMDB-COMPANY", "SNOW-CMDB-ASSIGN"],
)
def test__of_asmsystemids(playbook_tasks_data, asm_system_id_types):
    key_found = helper.was_grid_field_value_found(
        playbook_tasks_data, "val1", asm_system_id_types
    )
    assert key_found
