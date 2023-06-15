import json
import io
import demistomock as demito
import pytest
from smc import *
# from smc.elements.network import IPList, DomainName
from Forcepoint_Security_Management_Center import (create_address_command, update_address_command, list_address_command,
                                                   delete_address_command, IPList)
from smc.api.exceptions import ElementNotFound
from smc.base.model import Element
from smc.base.collection import CollectionManager

class mock_IPList():
    def __init__(self, name: str, iplist: list, comment: str):
        self.name = name
        self.iplist = iplist
        self.comment = comment


def test_create_address_command(mocker):
    """
    Given:
        - demisto args
    When:
        - Calling function create_address_command
    Then:
        - Ensure the results holds the expected data
    """

    args = {
        'name': 'name',
        'addresses': '1.1.1.1,8.8.8.8',
        'comment': 'comment'
    }
    mocker.patch.object(IPList, 'create', return_value=mock_IPList(name='name', iplist=['1.1.1.1', '8.8.8.8'], comment='comment'))
    response = create_address_command(args)

    assert response.readable_output == 'IP List name was created successfully.'
    assert response.outputs.get('Name') == 'name'


@pytest.mark.parametrize('is_overwrite,returned_iplist', [(True, ['1.2.3.4']), (False, ['1.1.1.1', '1.2.3.4'])])
def test_update_address_command(mocker, is_overwrite, returned_iplist):
    """
    Given:
        - demisto args
        Case 1: ovrwriting the existing ip list
        Case 2: appending to the existing list
    When:
        - Calling function update_address_command
    Then:
        - Ensure the results holds the expected data
    """

    args = {
        'name': 'name',
        'addresses': '1.2.3.4',
        'comment': 'new_comment',
        'is_overwrite': is_overwrite
    }
    mocker.patch.object(IPList, 'update_or_create', return_value=mock_IPList(name='name',
                                                                             iplist=returned_iplist,
                                                                             comment='new_comment'))
    response = update_address_command(args)

    assert response.readable_output == 'IP List name was updated successfully.'
    assert response.outputs.get('Addresses') == returned_iplist


@pytest.mark.parametrize('args,returned_results', [({'name': 'name'}, 1), ({'limit': '2'}, 2), ({'all_results': 'True'}, 3)])
def test_list_address_command(mocker, args, returned_results):
    """
    Given:
        - demisto args:
        Case 1: stating a specific IPList name
        Case 2: getting 2 results
        Case 3: getting all of the results (3 results)
    When:
        - Calling function list_address_command
    Then:
        - Ensure the results holds the expected data and the correct number of results
    """

    ip_list = mock_IPList(name='name', iplist=['1.1.1.1'], comment='new_comment')
    mocker.patch.object(CollectionManager, 'filter', return_value=[ip_list])
    mocker.patch.object(CollectionManager, 'limit', return_value=[ip_list, ip_list])
    mocker.patch.object(CollectionManager, 'all', return_value=[ip_list, ip_list, ip_list])
    response = list_address_command(args)

    assert 'IP Lists' in response.readable_output
    assert len(response.outputs) == returned_results


def delete():
    raise ElementNotFound


def test_delete_address_command(mocker):
    """
    Given:
        - demisto args
    When:
        - Calling function delete_address_command
    Then:
        - Ensure the results holds the expected data in case of an ElementNotFound exception
    """

    mocker.patch.object(IPList, 'delete', side_effect=delete)
    response = delete_address_command({'name': 'name'})

    assert response.readable_output == 'IP List name was not found.'
