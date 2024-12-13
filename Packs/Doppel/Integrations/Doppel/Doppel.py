import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
"""Doppel for Cortex XSOAR (aka Demisto)

This integration contains features to mirror the alerts from Doppel to create incidents in XSOAR
and the commands to perform different updates on the alerts
"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """
    
    def __init__(self, base_url, api_key):
        super().__init__(base_url)
        self._headers = dict()
        self._headers["accept"] = "application/json"
        self._headers["x-api-key"] = api_key


    def get_alert(self, id: str, entity: str) -> Dict[str, str]:
        """Return the alert's details when provided the Alert ID or Entity as input

        :type id: ``str``
        :param id: Alert id for which we need to fetch details
        
        :type entity: ``str``
        :param entity: Alert id for which we need to fetch details

        :return: dict as with alert's details
        :rtype: ``dict``
        """
        params: dict = {}
        if id:
            params['id'] = id
        if entity:
            params['entity'] = entity

        response_content = self._http_request(
            method="GET",
            url_suffix='alert',
            params=params
        )
        return response_content
    
    def update_alert(
                self,
                queue_state: str,
                entity_state: str,
                alert_id: Optional[str] = None,
                entity: Optional[str] = None,
            ) -> Dict[str, Any]:
        """
        Updates an existing alert using either the alert ID or the entity.

        :param queue_state: The queue state to update to.
        :param entity_state: The entity state to update to.
        :param alert_id: The alert ID (optional).
        :param entity: The entity (optional).
        :return: JSON response containing the updated alert.
        """
        if alert_id and entity:
            raise ValueError("Only one of 'alert_id' or 'entity' can be specified, not both.")
        if not alert_id and not entity:
            raise ValueError("Either 'alert_id' or 'entity' must be specified.")

        api_name = "alert"
        api_url = f"{self._base_url}/{api_name}"
        params = {"id": alert_id} if alert_id else {"entity": entity}
        payload = {"queue_state": queue_state, "entity_state": entity_state}

        response_content = self._http_request(
            method="PUT",  # Changed to PUT as per reference
            full_url=api_url,
            params=params,
            json_data=payload,
        )
        return response_content
    
    def get_alerts(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fetches multiple alerts based on query parameters.

        :param params: A dictionary of query parameters to apply to the request.
        :return: A list of dictionaries containing alert details.
        """
        api_name = "alerts"
        api_url = f"{self._base_url}/{api_name}"
        # Filter out None values
        filtered_params = {k: v for k, v in params.items() if v is not None}

        demisto.debug(f"API Request Params: {filtered_params}")

        # Use params as query parameters, not json_data
        response_content = self._http_request(
            method="GET",
            full_url=api_url,
            params=filtered_params
        )
        return response_content
    
    def create_alert(self, entity: str) -> Dict[str, Any]:
        api_name = "alert"
        api_url = f"{self._base_url}/{api_name}"
        response_content = self._http_request(
            method="POST",
            full_url=api_url,
            json_data={"entity": entity}
        )
        return response_content

''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.password
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    id: str = args.get('id', None)
    entity: str = args.get('entity', None)
    if not id and not entity:
        raise ValueError('Neither id nor the entity is specified. We need exactly single input for this command')
    if id and entity:
        raise ValueError('Both id and entity is specified. We need exactly single input for this command')
    
    result = client.get_alert(id=id, entity=entity)

    return CommandResults(
        outputs_prefix='Doppel.Alert',
        outputs_key_field='id',
        outputs=result,
    )

def update_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Executes the update alert command.

    :param client: The Client instance.
    :param args: Command arguments.
    :return: CommandResults object.
    """
    alert_id = args.get('alert_id')
    entity = args.get('entity')
    queue_state = args.get('queue_state')
    entity_state = args.get('entity_state')

    if alert_id and entity:
        raise ValueError("Only one of 'alert_id' or 'entity' can be specified.")
    if not queue_state or not entity_state:
        raise ValueError("Both 'queue_state' and 'entity_state' must be specified.")

    result = client.update_alert(queue_state=queue_state, entity_state=entity_state, alert_id=alert_id, entity=entity)

    return CommandResults(
        outputs_prefix='Doppel.UpdatedAlert',
        outputs_key_field='id',
        outputs=result,
    )

def get_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command to fetch multiple alerts based on query parameters.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object with the retrieved alerts.
    """

    # Extract query parameters directly from arguments
    query_params = {
        'search_key': args.get('search_key'),
        'queue_state': args.get('queue_state'),
        'product': args.get('product'),
        'created_before': args.get('created_before'),
        'created_after': args.get('created_after'),
        'sort_type': args.get('sort_type'),
        'sort_order': args.get('sort_order'),
        'page': args.get('page'),
        'tags': args.get('tags')
    }

    # Call the client's `get_alerts` method to fetch data
    demisto.debug(f"Query parameters before sending to client: {query_params}")
    results = client.get_alerts(params=query_params)
    demisto.debug(f"Results received: {results}")

    # Handle empty alerts response
    if not results:
        raise ValueError("No alerts were found with the given parameters.")

    # Prepare the readable JSON response
    readable_output = json.dumps(results, indent=4)

    return CommandResults(
        outputs_prefix="Doppel.GetAlerts",
        outputs_key_field="id",
        outputs=results,
        readable_output=readable_output
    )

def create_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    entity = args.get('entity')
    if not entity:
        raise ValueError("Entity must be specified to create an alert.")

    result = client.create_alert(entity=entity)

    return CommandResults(
        outputs_prefix='Doppel.CreatedAlert',
        outputs_key_field='id',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/v1')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key)

        current_command: str = demisto.command()
        if current_command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif current_command == 'get-alert':
            return_results(get_alert_command(client, demisto.args()))
        elif current_command == 'update-alert':
            return_results(update_alert_command(client, demisto.args()))
        elif current_command == 'get-alerts':
            return_results(get_alerts_command(client, demisto.args()))
        elif current_command == 'create-alert':
            return_results(create_alert_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
