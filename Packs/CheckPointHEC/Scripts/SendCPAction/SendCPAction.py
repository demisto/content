from CommonServerPython import *


def send_action_and_update_incident(farm: str, customer: str, entity: str, action: str):
    result = demisto.executeCommand(
        "checkpointhec-send-action",
        {
            'farm': farm,
            'customer': customer,
            'entity': entity,
            'action': action,
        }
    )
    demisto.executeCommand(
        "setIncident",
        {
            'customFields': json.dumps({
                'checkpointhectask': result[0]['Contents']['task']
            })
        }
    )
    return result


def main():  # pragma: no cover
    try:
        args = demisto.args()
        farm = args.get('farm')
        customer = args.get('customer')
        entity = args.get('entity')
        action = args.get('action')
        return_results(send_action_and_update_incident(farm, customer, entity, action))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
