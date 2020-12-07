import os
from Tests.Marketplace.prepare_private_id_set_for_merge import remove_old_pack_from_private_id_set


def test_remove_old_pack_from_private_id_set():
    workday_pack = {
            "Workday": {
                "pack": "Workday"
            }
        }

    Feedsslabusech_pack = {
            "abuse.ch SSL Blacklist Feed": {
                "pack": "Feedsslabusech"
            }
        }
    private_id_set = remove_old_pack_from_private_id_set(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                      "test_data", "id_set.json"), 'Workday')
    assert workday_pack not in private_id_set['integrations']

    private_id_set = remove_old_pack_from_private_id_set(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                      "test_data", "id_set.json"), 'Feedsslabusech')
    assert Feedsslabusech_pack not in private_id_set['integrations']

    private_id_set = remove_old_pack_from_private_id_set(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                      "test_data", "id_set.json"), '')
    assert Feedsslabusech_pack in private_id_set['integrations']
    assert workday_pack in private_id_set['integrations']