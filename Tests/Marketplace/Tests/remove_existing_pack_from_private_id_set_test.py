from Tests.Marketplace.remove_existing_pack_from_private_id_set import remove_old_pack_from_private_id_set


PRIVATE_ID_SET = {
    "scripts": [],
    "playbooks": [],
    "integrations": [
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
        "Accessdata": {
            "name": "Accessdata"
        },
        "ActiveMQ": {
            "name": "ActiveMQ"
        },
        "Access data": {
            "id": "Accessdata"
        },
        "Active MQ": {
            "id": "ActiveMQ"
        },
    }
}

ACCESSDATA_INTEGRATION = {"Accessdata": {"name": "Accessdata", "pack": "Accessdata"}}
ACCESSDATA_PACK_NAMES = ["Accessdata", "Access data"]  # For 2 versions of Packs that can be inside the ID set

ACTIVEMQ_INTEGRATION = {"ActiveMQ": {"name": "ActiveMQ", "pack": "ActiveMQ"}}
ACTIVEMQ_PACK_NAMES = ["ActiveMQ", "Active MQ"]  # For 2 versions of Packs that can be inside the ID set


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

    private_id_set = remove_old_pack_from_private_id_set(PRIVATE_ID_SET, 'Accessdata')
    pack_names_list = list(private_id_set.get('Packs').keys())

    assert ACCESSDATA_INTEGRATION not in private_id_set['integrations']

    for name in ACCESSDATA_PACK_NAMES:
        assert name not in pack_names_list

    private_id_set = remove_old_pack_from_private_id_set(PRIVATE_ID_SET, '')
    pack_names_list = list(private_id_set.get('Packs').keys())

    assert ACTIVEMQ_INTEGRATION in private_id_set['integrations']

    for name in ACTIVEMQ_PACK_NAMES:
        assert name in pack_names_list
