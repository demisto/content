from contextlib import contextmanager

from demisto_client.demisto_api import IncidentWrapper
from demisto_client.demisto_api.models.feed_indicator import FeedIndicator
from demisto_sdk.commands.common.clients import XsoarClient
from demisto_client.demisto_api.rest import ApiException
from demisto_sdk.commands.common.tools import retry
from Tests.scripts.utils import logging_wrapper as logging


@contextmanager
def save_indicators(client: XsoarClient, indicators: list[FeedIndicator]):
    """
    Creates indicators

    Args:
        client (XsoarClient): xsoar-saas client.
        indicators (List[FeedIndicator]]): the indicators to create

    """
    indicators_to_remove = []
    try:
        for indicator in indicators:
            try:
                response = client.create_indicator(
                    indicator.value, indicator_type=indicator.type, score=indicator.score)
                if created_indicator_id := response.get("id"):
                    logging.info(f'Created indicator {indicator.value} which is type {indicator.type}')
                    indicators_to_remove.append(created_indicator_id)
            except ApiException as e:
                if "it is in the exclusion list" not in e.reason:
                    raise
        yield
    finally:
        client.delete_indicators(indicators_to_remove)
        logging.info(f'Deleted indicators {indicators_to_remove}')


@contextmanager
def save_integration_instance(
    client: XsoarClient,
    integration_params: dict,
    integration_id: str,
    is_long_running: bool = False,
    instance_name: str | None = None,
    should_run_test_module: bool = True
):
    """
    Creates an integration instance

    Args:
        client (XsoarClient): xsoar client (saas/on-prem/xsiam).
        integration_params (dict): the integration instance data.
        integration_id (str): name of the integration ID to create the instance
        is_long_running (bool): whether the integration is long-running or not.
        instance_name (str): the instance name to create to integration
        should_run_test_module (bool): whether to run the test-module for the integration

    Yields:
        the raw api response of the newly created integration instance
    """
    created_instance_uuid = ""
    name = instance_name or f"end-to-end-{integration_id}"
    try:
        response = client.create_integration_instance(
            _id=integration_id,
            instance_name=name,
            integration_instance_config=integration_params,
            integration_log_level="Verbose",
            is_long_running=is_long_running,
            should_test=should_run_test_module
        )
        logging.info(
            f'Created integration instance {integration_id} with name {name} as long-running-integration={is_long_running}')
        created_instance_uuid = response.get("id")
        yield response
    finally:
        if created_instance_uuid:
            client.delete_integration_instance(created_instance_uuid)
            logging.info(f'Deleted integration instance {integration_id} with name {name}')


@contextmanager
def save_incident(
    client: XsoarClient, name: str | None = None, playbook_id: str | None = None
) -> IncidentWrapper:
    """
    Creates an incident

    Args:
        client (XsoarClient): xsoar client (saas/on-prem/xsiam).
        name (dict): the name of the incident.
        playbook_id (str): playbook ID that the incident will be attached to.

    Yields:
        the raw api response of the newly created incident
    """
    incident_id = None
    incident_name = name or f'end-to-end-{playbook_id}-incident'
    try:
        response = client.create_incident(
            incident_name, should_create_investigation=True, attached_playbook_id=playbook_id
        )
        logging.info(f'Created incident {incident_name} that will run the playbook {playbook_id}')
        incident_id = response.id
        yield response
    finally:
        if incident_id:
            client.delete_incidents(incident_id)
            logging.info(f'Removed incident {incident_name}')


@contextmanager
def save_playbook(xsoar_client: XsoarClient, playbook_path: str, playbook_id: str, playbook_name: str):
    """
    Saves a playbook

    Args:
        xsoar_client (XsoarClient): xsoar client (saas/on-prem/xsiam).
        playbook_path (dict): path to the playbook yml
        playbook_id (str): the ID of the playbook
        playbook_name (str): the name of the playbook
    """
    try:
        xsoar_client.client.import_playbook(playbook_path)
        logging.info(f'Created playbook {playbook_id}')
        yield
    finally:
        xsoar_client.delete_playbook(playbook_name, playbook_id)
        logging.info(f'Deleted playbook {playbook_id}')


def get_integration_instance_name(integration_params: dict, default: str) -> str:
    """
    Gets an instance name for the integration.
    """
    return integration_params.pop(
        "integrationInstanceName", f'e2e-test-{integration_params.get("name", default)}'
    )


@contextmanager
def get_fetched_incident(
    client: XsoarClient,
    source_instance_name: str,
    incident_ids: list | str | None = None,
    from_date: str | None = None,
    incident_types: list | str | None = None,
    should_start_investigation: bool = True,
    should_remove_fetched_incidents: bool = True,
):
    """
    Queries for a fetched incident against several filters and bring it back.

    Args:
        client (XsoarClient): xsoar client (saas/on-prem/xsiam).
        source_instance_name (str): the instance name that fetched the incident
        incident_ids (dict): the incident ID(s) to filter against them
        from_date (str): from which date to start querying the incident search
        incident_types (str): the incident type(s) to filter against them
        should_start_investigation (bool): whether investigation should be started when finding the relevant incident
                                           (means that the playbook attached to the incident will start running).
        should_remove_fetched_incidents (bool): whether to remove all the fetched incidents during teardown.

    Yields:
        dict: a fetched incident that was found.
    """
    @retry(times=30, delay=3)
    def _get_fetched_incident():
        _found_incidents = client.search_incidents(
            incident_ids, from_date=from_date, incident_types=incident_types, source_instance_name=source_instance_name, size=1
        )
        if data := _found_incidents.get("data"):
            return data
        raise Exception(
            f'Could not get incident with filters: {incident_ids=}, {from_date=}, {incident_types=}'
        )

    try:
        found_incidents = _get_fetched_incident()
        amount_of_found_incidents = len(found_incidents)
        assert amount_of_found_incidents == 1, f'Found {amount_of_found_incidents} incidents'
        incident = found_incidents[0]
        if incident_types:
            assert incident["type"] == incident_types, f'Found wrong incident {incident} type(s)'

        if should_start_investigation:
            incident_id = incident.get("id")
            assert incident_id, f'Could not find incident ID from response {incident}'
            start_investigation_response = client.start_incident_investigation(incident_id)
            incident["investigationId"] = start_investigation_response.get("response", {}).get("id")

        logging.info(f'Found the following incident {incident.get("name")}')
        yield incident

    finally:
        if should_remove_fetched_incidents:
            # removes all the fetched incidents found with the filters
            incidents_to_remove = client.search_incidents(
                incident_ids, from_date=from_date, incident_types=incident_types
            )
            if incident_ids_to_remove := [_incident.get("id") for _incident in incidents_to_remove.get("data", [])]:
                client.delete_incidents(incident_ids_to_remove)
                logging.info(f'Removed successfully incidents {incident_ids_to_remove}')
