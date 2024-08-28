from CommonServerPython import *


def send_action_and_update_incident(entity: str, action: str, incident: str):
    result = demisto.executeCommand(
        "checkpointhec-send-action",
        {
            'entity': entity,
            'action': action,
            'using': incident
        }
    )
    demisto.executeCommand(
        "setIncident",
        {
            'customFields': json.dumps({
                'checkpointhecemailtask': result[0]['Contents']['task']
            })
        }
    )
    return result


def main():  # pragma: no cover
    try:
        incident = demisto.incident()['sourceInstance']
        args = demisto.args()
        entity = args.get('entity')
        action = args.get('action')
        return_results(send_action_and_update_incident(entity, action, incident))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
