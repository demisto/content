import json
import io
import demistomock as demisto
import pytest
from smc import *
from Forcepoint_Security_Management_Center import (create_iplist_command, update_iplist_command, list_iplist_command,
                                                   delete_iplist_command, create_host_command, list_host_command,
                                                   delete_host_command, update_host_command, create_domain_command,
                                                   list_domain_command, delete_domain_command, IPList, Host, DomainName)
from smc.api.exceptions import ElementNotFound
from smc.base.model import Element
from smc.base.collection import CollectionManager


class mock_IPList():
    def __init__(self, name: str, iplist: list, comment: str):
        self.name = name
        self.iplist = iplist
        self.comment = comment


class mock_Host():
    def __init__(self, name: str, address: str, ipv6_address: str, secondary: str, comment: str):
        self.name = name
        self.address = address
        self.ipv6_address = ipv6_address
        self.secondary = secondary
        self.comment = comment


class mock_Domain():
    def __init__(self, name: str, comment: str):
        self.name = name
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
    response = create_iplist_command(args)

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
    ip_list = mock_IPList(name='name', iplist=returned_iplist, comment='new_comment')
    mocker.patch.object(CollectionManager, 'filter', return_value=[ip_list])
    mocker.patch.object(IPList, 'update_or_create', return_value=ip_list)
    response = update_iplist_command(args)

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
    response = list_iplist_command(args)

    assert 'IP Lists' in response.readable_output
    assert len(response.outputs) == returned_results


def mock_delete():
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

    mocker.patch.object(IPList, 'delete', side_effect=mock_delete)
    response = delete_iplist_command({'name': 'name'})

    assert response.readable_output == 'IP List name was not found.'


def test_create_host_command(mocker):
    """
    Given:
        - demisto args
    When:
        - Calling function create_host_command
    Then:
        - Ensure the results holds the expected data
    """

    args = {
        'name': 'name',
        'address': '1.1.1.1',
        'comment': 'comment'
    }
    mocker.patch.object(Host, 'create', return_value=mock_Host(name='name', address='1.1.1.1',
                                                               ipv6_address='', secondary='', comment='comment'))
    response = create_host_command(args)

    assert response.readable_output == 'Host name was created successfully.'
    assert response.outputs.get('Name') == 'name'


@pytest.mark.parametrize('args,returned_results', [({'name': 'name'}, 1), ({'limit': '2'}, 2), ({'all_results': 'True'}, 3)])
def test_list_host_command(mocker, args, returned_results):
    """
    Given:
        - demisto args:
        Case 1: stating a specific IPList name
        Case 2: getting 2 results
        Case 3: getting all of the results (3 results)
    When:
        - Calling function list_host_command
    Then:
        - Ensure the results holds the expected data and the correct number of results
    """
 
    host = mock_Host(name='name', address='1.1.1.1', ipv6_address='', secondary='', comment='comment')
    mocker.patch.object(CollectionManager, 'filter', return_value=[host])
    mocker.patch.object(CollectionManager, 'limit', return_value=[host, host])
    mocker.patch.object(CollectionManager, 'all', return_value=[host, host, host])
    response = list_host_command(args)

    assert 'Hosts:' in response.readable_output
    assert len(response.outputs) == returned_results


@pytest.mark.parametrize('is_overwrite,returned_host', [(True, ['1.2.3.4']), (False, ['1.1.1.1', '1.2.3.4'])])
def test_update_host_command(mocker, is_overwrite, returned_host):
    """
    Given:
        - demisto args
        Case 1: overwriting the existing host
        Case 2: appending to the existing host
    When:
        - Calling function update_host_command
    Then:
        - Ensure the results holds the expected data
    """

    args = {
        'name': 'name',
        'address': '1.2.3.4',
        'comment': 'new_comment',
        'is_overwrite': is_overwrite
    }
    host = mock_Host(name='name', address='1.1.1.1', ipv6_address='', secondary=returned_host, comment='comment')
    mocker.patch.object(CollectionManager, 'filter', return_value=[host])
    mocker.patch.object(Host, 'update_or_create', return_value=host)
    response = update_host_command(args)

    assert response.readable_output == 'Host name was updated successfully.'
    assert response.outputs.get('Secondary_address') == returned_host


def mock_return_error(error_str: str):

    raise Exception(error_str)


def test_update_host_with_host_not_found(mocker):
    """
    Given:
        - name of host
    When:
        - Calling function update_host_command
    Then:
        - Ensure the exception is raised with the correct data when a host to update was not found
    """
    args = {
        'name': 'name',
    }
    mocker.patch('Forcepoint_Security_Management_Center.return_error', side_effect=mock_return_error)
    with pytest.raises(Exception) as e:
        mocker.patch.object(CollectionManager, 'filter', return_value=[])
        update_host_command(args)
        assert str(e) == "Host name was not found"


def test_update_iplist_with_iplist_not_found(mocker):
    """
    Given:
        - name of host
    When:
        - Calling function update_host_command
    Then:
        - Ensure the exception is raised with the correct data when a host to update was not found
    """
    args = {
        'name': 'name',
    }
    mocker.patch('Forcepoint_Security_Management_Center.return_error', side_effect=mock_return_error)
    with pytest.raises(Exception) as e:
        mocker.patch.object(CollectionManager, 'filter', return_value=[])
        update_iplist_command(args)
        assert str(e) == "IP List name was not found"


def test_delete_host_command(mocker):
    """
    Given:
        - demisto args
    When:
        - Calling function delete_host_command
    Then:
        - Ensure the results holds the expected data in case of an ElementNotFound exception
    """

    mocker.patch.object(Host, 'delete', side_effect=delete)
    response = delete_host_command({'name': 'name'})

    assert response.readable_output == 'Host name was not found.'


def test_create_domain_command(mocker):
    """
    Given:
        - demisto args
    When:
        - Calling function create_domain_command
    Then:
        - Ensure the results holds the expected data
    """

    args = {
        'name': 'name',
        'comment': 'comment'
    }
    mocker.patch.object(DomainName, 'create', return_value=mock_Domain(name='name', comment='comment'))
    response = create_domain_command(args)

    assert response.readable_output == 'Domain name was created successfully.'
    assert response.outputs.get('Name') == 'name'


@pytest.mark.parametrize('args,returned_results', [({'name': 'name'}, 1), ({'limit': '2'}, 2), ({'all_results': 'True'}, 3)])
def test_list_domain_command(mocker, args, returned_results):
    """
    Given:
        - demisto args:
        Case 1: stating a specific Domain name
        Case 2: getting 2 results
        Case 3: getting all of the results (3 results)
    When:
        - Calling function list_domain_command
    Then:
        - Ensure the results holds the expected data and the correct number of results
    """

    domain = mock_Domain(name='name', comment='comment')
    mocker.patch.object(CollectionManager, 'filter', return_value=[domain])
    mocker.patch.object(CollectionManager, 'limit', return_value=[domain, domain])
    mocker.patch.object(CollectionManager, 'all', return_value=[domain, domain, domain])
    response = list_domain_command(args)

    assert 'Domains:' in response.readable_output
    assert len(response.outputs) == returned_results


def test_delete_domain_command(mocker):
    """
    Given:
        - demisto args
    When:
        - Calling function delete_domain_command
    Then:
        - Ensure the results holds the expected data in case of an ElementNotFound exception
    """

    mocker.patch.object(Host, 'delete', side_effect=delete)
    response = delete_host_command({'name': 'name'})

    assert response.readable_output == 'Host name was not found.'
