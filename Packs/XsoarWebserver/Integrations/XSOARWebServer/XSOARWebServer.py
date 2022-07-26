import uuid
from bottle import route, run


@route('/hello')
def hello():
    return "Hello World!"


@route('/process/<uuid>/<action>')
def process_call(uuid, action):
    integration_context = get_integration_context()
    try:
        data = integration_context[uuid]
        if action not in data['input_list']:
            raise KeyError
        data["response"] = action
        data["response_received"] = True
        integration_context[uuid] = data
        set_integration_context(integration_context)
        return "Captured response successfully"
    except KeyError:
        return "Cannot process action, server error"


def run_long_running(listen_port):
    run(host='0.0.0.0', port=listen_port, debug=True)


def run_setup_action():
    port = demisto.params().get('longRunningPort')
    inc = demisto.incident()
    integration_context = get_integration_context()
    entry_uuid = str(uuid.uuid4())
    input_list = demisto.args().get('actions').split(',')
    integration_context[entry_uuid] = {"type": "simple_action", "inc_id": inc['id'],
                                       "input_list": input_list, "response": "", "response_received": False}
    set_integration_context(integration_context)
    context_list = []
    xsoar_external_url = demisto.params().get('xsoar-external-url').rstrip('/')
    integration_instance_name = demisto.integrationInstance()
    partial_link = f'{xsoar_external_url}/instance/execute/{integration_instance_name}/process/{entry_uuid}/'
    partial_link_port = f'{xsoar_external_url}:{port}/instance/execute/{integration_instance_name}/process/{entry_uuid}/'
    for action in input_list:
        context_list.append({"action_url": partial_link + action,
                             "action_url_port": partial_link_port + action,
                             "uuid": entry_uuid, "action_string": action})
    to_return = CommandResults(outputs_prefix='WS-ActionDetails', outputs=context_list)
    return_results(to_return)


def run_clear_integration_cache():
    set_integration_context({})
    return_results("cleared backend cache")


def run_show_integration_cache():
    ic = get_integration_context()
    return_results(json.dumps(ic))


def run_remove_action():
    uuid = demisto.args().get('uuid')
    integration_context = get_integration_context()
    integration_context.pop(uuid)
    set_integration_context(integration_context)


def run_get_action_status():
    uuid = demisto.args().get('uuid')
    integration_context = get_integration_context()
    lookup = False
    try:
        data = integration_context[uuid]
        data['uuid'] = uuid
        lookup = True
    except KeyError:
        return_results("Action lookup failed; please check the UUID")
    if lookup:
        to_return = CommandResults(outputs_prefix='ws-action-status(val.uuid==obj.uuid)', outputs=data)
        return_results(to_return)


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    listen_port = demisto.params().get('longRunningPort')
    command = demisto.command()

    try:
        if command == 'long-running-execution':
            run_long_running(listen_port)
        elif command == 'test-module':
            pass
        elif command == 'xsoar-ws-setup-simple-action':
            run_setup_action()
        elif command == 'xsoar-ws-clear-cache':
            run_clear_integration_cache()
        elif command == 'xsoar-ws-show-cache':
            run_show_integration_cache()
        elif command == 'xsoar-ws-get-action-status':
            run_get_action_status()
        elif command == 'xsoar-ws-remove-action':
            run_remove_action()
        else:
            return_error('Command not found')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
