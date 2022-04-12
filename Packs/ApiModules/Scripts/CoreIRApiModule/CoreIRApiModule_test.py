import pytest

from CoreIRApiModule import CoreClient

test_client = CoreClient(
    base_url='https://test_api.com/public_api/v1', headers={}
)


def test_get_incidents():
    with pytest.raises(ValueError, match='Should be provide either sort_by_creation_time or '
                                         'sort_by_modification_time. Can\'t provide both'):
        test_client.get_incidents(sort_by_creation_time="asc",
                                  sort_by_modification_time="desc")


def test_update_incident():
    with pytest.raises(ValueError, match="Can't provide both assignee_email/assignee_name and unassign_user"):
        test_client.update_incident(incident_id='1',
                                    status='new',
                                    unassign_user="user",
                                    assigned_user_mail="user")


