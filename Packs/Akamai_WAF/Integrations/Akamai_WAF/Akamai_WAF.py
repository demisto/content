""" IMPORTS """
# Std imports

# 3-rd party imports
from typing import Dict, Tuple, Union, Optional, List
import requests
import urllib3
# Local imports
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from akamai.edgegrid import EdgeGridAuth

"""GLOBALS/PARAMS

Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.
        
    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'Akamai WAF'
INTEGRATION_CONTEXT_NAME = 'Akamai'

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def test_module(self) -> Dict:
        """
            Performs basic GET request to check if the API is reachable and authentication is successful.
        Returns:
            Response dictionary
        """
        return self.get_network_lists(extended=False, include_elements=False)

    def get_network_lists(self,
                          search: str = None,
                          list_type: str = None,
                          extended: bool = True,
                          include_elements: bool = True,
                          ) -> dict:
        """
            Get network lists
        Args:
            search: Only list items that match the specified substring in any network list’s name or list of items.
            list_type: Filters the output to lists of only the given type of network lists if provided, either IP or GEO.
            extended: Whether to return extended details in the response
            include_elements: Whether to return all list items.

        Returns:
            Json response as dictionary
        """
        params = {
            "search": search,
            "listType": list_type,
            "extended": extended,
            "includeElements": include_elements,
        }
        return self._http_request(method='GET',
                                  url_suffix='/network-list/v2/network-lists',
                                  params=params)

    def get_network_list_by_id(self, network_list_id: str) -> dict:
        """
            Get network list by ID
        Args:
            network_list_id: network list ID

        Returns:
            Json response as dictionary
        """
        params = {
            "extended": True,
            "includeElements": True
        }
        return self._http_request(method='GET',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}',
                                  params=params)

    def create_network_list(self, list_name: str, list_type: str, elements: Optional[Union[list, str]],
                            description: Optional[str] = None) -> dict:
        """
            Create network list
        Args:
            list_name: List name
            list_type: List type, e.g. IP
            description: Description of the list
            elements: list values

        Returns:
            Json response as dictionary
        """
        body = {
            "name": list_name,
            "type": list_type,
            "description": description,
            "list": elements if elements else []
        }
        return self._http_request(method='POST',
                                  url_suffix='/network-list/v2/network-lists',
                                  json_data=body)

    def delete_network_list(self, network_list_id: str) -> dict:
        """
            Delete network list by ID
        Args:
            network_list_id: network list ID

        Returns:
            Json response as dictionary
        """
        return self._http_request(method='DELETE',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}',
                                  resp_type='response')

    def activate_network_list(self, network_list_id: str, env: str, comment: Optional[str],
                              notify: Optional[list]) -> dict:
        """
            Activating network list in STAGING or PRODUCTION
        Args:
            network_list_id: Network list ID
            env: Staging/Production
            comment: Comment to be logged
            notify: List of email to be notified on activation

        Returns:
            Json response as dictionary
        """
        body = {
            "comments": comment,
            "notificationRecipients": notify
        }
        return self._http_request(method='POST',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}/environments/{env}'
                                             f'/activate',
                                  json_data=body,
                                  resp_type='response')

    def add_elements_to_network_list(self, network_list_id: str, elements: Optional[Union[list, str]]) -> dict:
        """
            Add elements to network list
        Args:
            network_list_id: Network list ID
            elements: List of value to append

        Returns:
            Json response as dictionary
        """
        body = {
            "list": elements
        }
        return self._http_request(method='POST',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}/append',
                                  json_data=body)

    def remove_element_from_network_list(self, network_list_id: str, element: str) -> dict:
        """
            Remove element from network list
        Args:
            network_list_id: Network list ID
            element: Element to remove

        Returns:
            Json response as dictionary
        """
        params = {
            'element': element
        }
        return self._http_request(method='DELETE',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}/elements',
                                  params=params,
                                  resp_type='response')

    def get_activation_status(self, network_list_id: str, env: str) -> dict:
        """
            Get activation status of network list in enviorment - Staging/Production
        Args:
            network_list_id: Network list ID
            env: Staging/Production

        Returns:
            Json response as dictionary
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}/environments/{env}/status')


''' HELPER FUNCTIONS '''


def get_network_lists_ec(raw_response: Optional[list]) -> Tuple[list, list]:
    """
        Get raw response list of networks from Akamai and parse to ec
    Args:
        raw_response: network list fro raw response

    Returns:
        List of network lists by entry context, entry context for human readable
    """
    entry_context = []
    human_readable = []
    if raw_response:
        for network in raw_response:
            entry_context.append(assign_params(**{
                "Name": network.get('name'),
                "Type": network.get('type'),
                "UniqueID": network.get('uniqueId'),
                "CreateDate": network.get('CreateDate'),
                "CreatedBy": network.get('createdBy'),
                "ExpeditedProductionActivationStatus": network.get('expeditedProductionActivationStatus'),
                "ExpeditedStagingActivationStatus": network.get('expeditedStagingActivationStatus'),
                "ProductionActivationStatus": network.get('productionActivationStatus'),
                "StagingActivationStatus": network.get('stagingActivationStatus'),
                "UpdateDate": network.get('updateDate'),
                "UpdatedBy": network.get('updatedBy'),
                "ElementCount": network.get('elementCount'),
                "Elements": network.get('list')
            }))
            human_readable.append(assign_params(**{
                "Name": network.get('name'),
                "Type": network.get('type'),
                "Unique ID": network.get('uniqueId'),
                "Updated by": network.get('updatedBy'),
                "Production Activation Status": network.get('productionActivationStatus'),
                "Staging Activation Status": network.get('stagingActivationStatus'),
                "Element count": network.get('elementCount'),
            }))
    return entry_context, human_readable


def get_list_from_file(entry_id: Optional[str]) -> list:
    """
        Get list of IPs and Geo from txt file
    Args:
        entry_id: Entry ID of uploaded file

    Returns:
        list of IP and Geo
    """
    elements: list = []
    try:
        list_path = demisto.getFilePath(entry_id)['path']
        with open(list_path) as list_file:
            elements += list_file.read().split('\n')
    except Exception as ex:
        return_error('Failed to open txt file: {}'.format(ex))
    return elements


''' COMMANDS '''


@logger
def test_module_command(client: Client, *_) -> Tuple[None, None, str]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        *_: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    results = client.test_module()
    if 'links' in results:
        return None, None, 'ok'
    raise DemistoException(f'Test module failed, {results}')


@logger
def get_network_lists_command(
        client: Client,
        search: str = None,
        list_type: str = None,
        extended: str = 'true',
        include_elements: str = 'true',
) -> Tuple[object, dict, Union[List, Dict]]:
    """Get network lists

    Args:
        client: Client object with request
        search: Only list items that match the specified substring in any network list’s name or list of items.
        list_type: Filters the output to lists of only the given type of network lists if provided, either IP or GEO.
        extended: Whether to return extended details in the response
        include_elements: Whether to return all list items.

    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: Dict = client.get_network_lists(
        search=search, list_type=list_type, extended=(extended == 'true'), include_elements=(include_elements == 'true')
    )
    if raw_response:
        title = f'{INTEGRATION_NAME} - network lists'
        entry_context, human_readable_ec = get_network_lists_ec(raw_response.get('networkLists'))
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.Lists(val.UniqueID && val.UniqueID == obj.UniqueID && val.UpdateDate &&"
            f" val.UpdateDate == obj.UpdateDate)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def get_network_list_by_id_command(client: Client, network_list_id: str) -> Tuple[object, dict, Union[List, Dict]]:
    """Get network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list

    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: Dict = client.get_network_list_by_id(network_list_id=network_list_id)
    if raw_response:
        title = f'{INTEGRATION_NAME} - network list {network_list_id}'
        entry_context, human_readable_ec = get_network_lists_ec([raw_response])
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.Lists(val.UniqueID && val.UniqueID == obj.UniqueID &&"
            f" val.UpdateDate && val.UpdateDate == obj.UpdateDate)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def create_network_list_command(client: Client, list_name: str, list_type: str, description: Optional[str] = None,
                                entry_id: Optional[str] = None, elements: Optional[Union[str, list]] = None) \
        -> Tuple[object, dict, Union[List, Dict]]:
    """
        Create network list

    Args:
        client: Client object with request
        list_name: Network list name
        list_type: Network list type IP/GEO
        description: Network list description
        entry_id: Entry ID of list file (Each line should have one IP or GEO)
        elements: Elements separated by commas

    Returns:
        human readable (markdown format), entry context and raw response
    """
    if entry_id:
        elements = get_list_from_file(entry_id)
    else:
        elements = argToList(elements)
    raw_response: dict = client.create_network_list(list_name=list_name,
                                                    list_type=list_type,
                                                    elements=elements,
                                                    description=description)
    entry_context, human_readable_ec = get_network_lists_ec([raw_response])
    if raw_response:
        title = f'{INTEGRATION_NAME} - network list {list_name} created successfully'
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.Lists(val.UniqueID && val.UniqueID == obj.UniqueID && val.UpdateDate &&"
            f" val.UpdateDate == obj.UpdateDate)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def delete_network_list_command(client: Client, network_list_id: str) -> Tuple[object, dict, Union[List, Dict]]:
    """Delete network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list

    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response = client.delete_network_list(network_list_id=network_list_id)
    if raw_response:
        human_readable = f'**{INTEGRATION_NAME} - network list {network_list_id} deleted**'
        return human_readable, {}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def activate_network_list_command(client: Client, network_list_ids: str, env: str, comment: Optional[str] = None,
                                  notify: Optional[str] = None) -> Tuple[object, dict, Union[List, Dict]]:
    """Activate network list by ID

    Args:
        client: Client object with request
        network_list_ids: Unique ID of network list
        env: STAGING or PRODUCTION
        comment: Comment to be logged
        notify: Email to notify on activation

    Returns:
        human readable (markdown format), entry context and raw response
    """
    network_list_ids = argToList(network_list_ids)
    human_readable = ""
    for network_list_id in network_list_ids:
        try:
            raw_response = client.activate_network_list(network_list_id=network_list_id,
                                                        env=env,
                                                        comment=comment,
                                                        notify=argToList(notify))
            if raw_response:
                human_readable += f'{INTEGRATION_NAME} - network list **{network_list_id}** activated on {env} **successfully**\n'
        except DemistoException as e:
            if "This list version is already active" in e.args[0]:
                human_readable += f'**{INTEGRATION_NAME} - network list {network_list_id} already active on {env}**\n'
        except requests.exceptions.RequestException:
            human_readable += f'{INTEGRATION_NAME} - Could not find any results for given query\n'

    return human_readable, {}, {}


@logger
def add_elements_to_network_list_command(client: Client, network_list_id: str, entry_id: Optional[str] = None,
                                         elements: Optional[Union[str, list]] = None) \
        -> Tuple[object, dict, Union[List, Dict]]:
    """Add elements to network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list
        entry_id: Entry ID of list file (Each line should have one IP or GEO)
        elements: Elements separated by commas

    Returns:
        human readable (markdown format), entry context and raw response
    """
    if entry_id:
        elements = get_list_from_file(entry_id)
    else:
        elements = argToList(elements)
    raw_response: dict = client.add_elements_to_network_list(network_list_id=network_list_id,
                                                             elements=elements)
    if raw_response:
        title = f'**{INTEGRATION_NAME} - elements added to network list {network_list_id} successfully**'
        human_readable = tableToMarkdown(name=title,
                                         t={'elements': elements},
                                         removeNull=True)
        return human_readable, {}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def remove_element_from_network_list_command(client: Client, network_list_id: str, element: str) -> \
        Tuple[object, dict, Union[List, Dict]]:
    """Remove element from network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list
        element: Element to be removed

    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: dict = client.remove_element_from_network_list(network_list_id=network_list_id,
                                                                 element=element)
    if raw_response:
        human_readable = f'**{INTEGRATION_NAME} - element {element} removed from network list {network_list_id} successfully**'
        return human_readable, {}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def get_activation_status_command(client: Client, network_list_ids: Union[str, list], env: str) \
        -> Tuple[object, dict, Union[List, Dict]]:
    """Get activation status

    Args:
        client: Client object with request
        network_list_ids: Unique ID of network list (can be list as a string)
        env: STAGING or PRODUCTION

    Returns:
        human readable (markdown format), entry context and raw response
    """
    network_list_ids = argToList(network_list_ids)
    raws = []
    ecs = []
    context_entry: Dict = {}
    human_readable = ""
    for network_list_id in network_list_ids:
        try:
            raw_response: dict = client.get_activation_status(network_list_id=network_list_id,
                                                              env=env)
            if raw_response:
                raws.append(raw_response)
                if env == "PRODUCTION":
                    ecs.append({
                        "UniqueID": network_list_id,
                        "ProductionStatus": raw_response.get('activationStatus')

                    })
                elif env == "STAGING":
                    ecs.append({
                        "UniqueID": network_list_id,
                        "StagingStatus": raw_response.get('activationStatus')

                    })
                human_readable += f"{INTEGRATION_NAME} - network list **{network_list_id}** is " \
                                  f"**{raw_response.get('activationStatus')}** in **{env}**\n"
        except DemistoException as e:
            if "The Network List ID should be of the format" in e.args[0]:
                human_readable += f"{INTEGRATION_NAME} - network list **{network_list_id}** canot be found\n"
        except requests.exceptions.RequestException:
            human_readable += f'{INTEGRATION_NAME} - Could not find any results for given query\n'

    if env == "PRODUCTION":
        context_entry = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.ActivationStatus(val.UniqueID == obj.UniqueID)": ecs
        }
    elif env == "STAGING":
        context_entry = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.ActivationStatus(val.UniqueID == obj.UniqueID)": ecs
        }

    return human_readable, context_entry, raws


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    client = Client(
        base_url=params.get('host'),
        verify=verify_ssl,
        proxy=proxy,
        auth=EdgeGridAuth(
            client_token=params.get('clientToken'),
            access_token=params.get('accessToken'),
            client_secret=params.get('clientSecret')
        )
    )
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        'akamai-get-network-lists': get_network_lists_command,
        'akamai-get-network-list-by-id': get_network_list_by_id_command,
        'akamai-create-network-list': create_network_list_command,
        'akamai-delete-network-list': delete_network_list_command,
        'akamai-activate-network-list': activate_network_list_command,
        'akamai-add-elements-to-network-list': add_elements_to_network_list_command,
        'akamai-remove-element-from-network-list': remove_element_from_network_list_command,
        'akamai-get-network-list-activation-status': get_activation_status_command
    }
    try:
        readable_output, outputs, raw_response = commands[command](client=client, **demisto.args())
        return_outputs(readable_output, outputs, raw_response)

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
