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
    "Mappers": [],
    "Packs": {
        "Workday": {
            "name": "Workday"
        },
        "Accessdata": {
            "name": "Accessdata"
        },
        "ActiveMQ": {
            "name": "ActiveMQ"
        },
        "Access data": {
            "id": "Accessdata"
        },
        "WORKDAY": {
            "id": "Workday"
        },
        "Active MQ": {
            "id": "ActiveMQ"
        },
    }
}

WORKDAY_INTEGRATION = {"Workday": {"name": "Workday", "pack": "Workday"}}
ACCESSDATA_INTEGRATION = {"Accessdata": {"name": "Accessdata", "pack": "Accessdata"}}
ACTIVEMQ_INTEGRATION = {"ActiveMQ": {"name": "ActiveMQ", "pack": "ActiveMQ"}}


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
    assert WORKDAY_INTEGRATION not in private_id_set['integrations']
    assert 'Workday' not in list(private_id_set.get('Packs').keys())
    assert "WORKDAY" not in list(private_id_set.get('Packs').keys())

    private_id_set = remove_old_pack_from_private_id_set(PRIVATE_ID_SET, 'Accessdata')
    assert ACCESSDATA_INTEGRATION not in private_id_set['integrations']
    assert "Accessdata" not in list(private_id_set.get('Packs').keys())
    assert "Access data" not in list(private_id_set.get('Packs').keys())

    private_id_set = remove_old_pack_from_private_id_set(PRIVATE_ID_SET, '')
    assert ACTIVEMQ_INTEGRATION in private_id_set['integrations']
    assert "ActiveMQ" in list(private_id_set.get('Packs').keys())
    assert "Active MQ" in list(private_id_set.get('Packs').keys())
