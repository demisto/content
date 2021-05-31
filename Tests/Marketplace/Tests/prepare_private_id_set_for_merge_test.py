from Tests.Marketplace.prepare_private_id_set_for_merge import remove_old_pack_from_private_id_set


PRIVATE_ID_SET = {
    "scripts": [],
    "playbooks": [],
    "integrations": [
        {
            "Workday": {
                "name": "Workday",
                "pack": "Workday"
            }
        },
        {
            "Accessdata": {
                "name": "Accessdata",
                "pack": "Accessdata"
            }
        },
        {
            "ActiveMQ": {
                "name": "ActiveMQ",
                "pack": "ActiveMQ"
            }
        }
    ],
    "TestPlaybooks": [],
    "Classifiers": [],
    "Dashboards": [],
    "IncidentFields": [],
    "IncidentTypes": [],
    "IndicatorFields": [],
    "IndicatorTypes": [],
    "Layouts": [],
    "Reports": [],
    "Widgets": [],
    "Mappers": []
}

WORKDAY_PACK = {"Workday": {"name": "Workday", "pack": "Workday"}}
ACCESSDATA_PACK = {"Accessdata": {"name": "Accessdata", "pack": "Accessdata"}}
ACTIVEMQ_PACK = {"ActiveMQ": {"name": "ActiveMQ", "pack": "ActiveMQ"}}


def test_remove_old_pack_from_private_id_set():
    """
    Given
    - private ID set - to prepare for merge with the new pack
    - new pack name - to remove the old data from the ID set
    When
    - remove the old new pack's data from private ID set
    Then
    - ensure that the private ID set not contain the old new pack's data
    - ensure that in case there is no pack name no error returns, and the ID set remains as it is
    """
    private_id_set = remove_old_pack_from_private_id_set(PRIVATE_ID_SET, 'Workday')
    assert WORKDAY_PACK not in private_id_set['integrations']

    private_id_set = remove_old_pack_from_private_id_set(PRIVATE_ID_SET, 'Accessdata')
    assert ACCESSDATA_PACK not in private_id_set['integrations']

    private_id_set = remove_old_pack_from_private_id_set(PRIVATE_ID_SET, '')
    assert ACTIVEMQ_PACK in private_id_set['integrations']
