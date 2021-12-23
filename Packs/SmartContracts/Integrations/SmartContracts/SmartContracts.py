import asyncio
import json
from collections import deque

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from web3 import Web3


def handle_event(web3, raw_event, incident_type):
    event = json.loads(Web3.toJSON(raw_event))
    transaction_hash = event.get('transactionHash')
    transaction = web3.eth.get_transaction(transaction_hash)
    event['gas'] = transaction.get('gas')
    event_dump = json.dumps(event)
    incident = [{
        'name': f'Smart Contract Event {transaction_hash}',
        'details': event_dump,
        'rawJSON': event_dump,
        'type': incident_type,
    }]
    demisto.createIncidents(incident)
    return event


async def event_loop(
    web3,
    contract,
    incident_type,
    block,
    event_type,
    argument_filters,
):
    try:
        sample_events_to_store = deque(maxlen=20)

        while True:
            if event_type == 'Approval':
                event_filter = contract.events.Approval.createFilter(
                    fromBlock=block,
                    argument_filters=argument_filters,
                    # argument_filters={
                    #     'value': 115792089237316195423570985008687907853269984665640564039457584007913129639935,
                    #     'owner': '0x02788b3452849601e63ca70ce7db72c30c3cfd18',
                    # }
                )
            elif event_type == 'Transfer':
                event_filter = contract.events.Transfer.createFilter(
                    fromBlock=block,
                    argument_filters=argument_filters,
                    # argument_filters={
                    #     'value': 115792089237316195423570985008687907853269984665640564039457584007913129639935,
                    #     'owner': '0x02788b3452849601e63ca70ce7db72c30c3cfd18',
                    # }
                )
            for event in event_filter.get_all_entries():
                integration_context = get_integration_context()
                event = handle_event(web3, event, incident_type)
                block = event['blockNumber'] + 1
                sample_events_to_store.append(event)
                sample_events = deque(json.loads(integration_context.get('sample_events', '[]')), maxlen=20)
                sample_events += sample_events_to_store
                integration_context['sample_events'] = list(sample_events)
                set_to_integration_context_with_retries(integration_context)
            await asyncio.sleep(2)
    except Exception as e:
        err = f'An error occurred in the long running loop: {e}'
        demisto.error(err)
        demisto.updateModuleHealth(f'{err} {event_type=} {block=} {argument_filters=}')


def fetch_samples() -> None:
    """Extracts sample events stored in the integration context and returns them as incidents

    Returns:
        None: No data returned.
    """
    integration_context = get_integration_context()
    sample_events = json.loads(integration_context.get('sample_events', '[]'))
    incidents = [{'rawJSON': json.dumps(event)} for event in sample_events]
    demisto.incidents(incidents)


def get_sample_events(store_samples: bool = False) -> None:
    """Extracts sample events stored in the integration context and returns them

    Args:
        store_samples (bool): Whether to store sample events in the integration context or not.

    Returns:
        None: No data returned.
    """
    integration_context = get_integration_context()
    sample_events = integration_context.get('sample_events')
    if sample_events:
        try:
            demisto.results(json.loads(sample_events))
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'Failed deserializing sample events - {e}')
    else:
        output = 'No sample events found.'
        if not store_samples:
            output += ' The "Store sample events for mapping" integration parameter ' \
                      'need to be enabled for this command to return results.'
        demisto.results(output)


def main():
    params: Dict = demisto.params()
    rpc_endpoint: str = params.get('rpc_endpoint', '')

    web3 = Web3(Web3.HTTPProvider(rpc_endpoint))
    abi = json.loads(params.get('abi'))
    contract = web3.eth.contract(abi=abi)
    incident_type = params.get('incidentType', '')
    block = int(params.get('block'))
    event_type = params.get('event_type')
    argument_filters = json.loads(params.get('arg_filter', '{}'))

    # TODO

    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    store_samples = params.get('store_samples', False)
    sock_read = int(params.get('sock_read_timeout', 120))

    LOG(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            demisto.results('ok')
        elif demisto.command() == 'long-running-execution':
            loop = asyncio.get_event_loop()
            try:
                loop.run_until_complete(
                    asyncio.gather(
                        event_loop(web3, contract, incident_type, block, event_type, argument_filters)
                    )
                )
            finally:
                loop.close()
        elif demisto.command() == 'fetch-incidents':
            fetch_samples()
    except Exception as e:
        error_msg = f'Error in Web3: {str(e)}'
        demisto.error(error_msg)
        demisto.updateModuleHealth(error_msg)
        return_error(error_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
