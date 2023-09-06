import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import uuid
from string import Template
from bottle import request, route, run


@route('/hello')
def hello():
    return "Hello World!"


@route('/process/<uuid>/<linkuuid>/<action>', method="GET")
def process_get(uuid, linkuuid, action):
    integration_context = get_integration_context()
    try:
        data = integration_context[uuid]
        if action not in data['input_list']:
            raise KeyError
        data["link_tracker"][linkuuid]["response"] = action
        data["link_tracker"][linkuuid]["response_received"] = True
        integration_context[uuid] = data
        set_integration_context(integration_context)
        response_html = '''<html><body>
                            <b>Thank you for responding, Your security team is grateful !</b>
                            </body>
                           </html>'''
        return response_html
    except KeyError:
        return "Cannot process action,server error"


@route('/processform/<uuid>/<linkuuid>/', method='POST')
def process_form(uuid, linkuuid):
    integration_context = get_integration_context()
    try:
        data = integration_context[uuid]
        data["link_tracker"][linkuuid]["response_received"] = True
        data["link_tracker"][linkuuid]["response"] = dict(request.forms.decode())  # pylint: disable=E1101
        integration_context[uuid] = data
        set_integration_context(integration_context)
        response_html = '''<html><body>
                            <b>Thank you for responding, Your security team is grateful !</b>
                            </body>
                           </html>'''
        return response_html
    except KeyError:
        return "Cannot process action,server error"


@route('/processform/<uuid>/<linkuuid>/', method='GET')
def process_form_get(uuid, linkuuid):
    integration_context = get_integration_context()
    try:
        data = integration_context[uuid]
        email_html = data["link_tracker"][linkuuid]["htmlemail"]
        return email_html
    except KeyError:
        return "Cannot process action,server error"


def run_long_running(listen_port):
    run(host='0.0.0.0', port=listen_port, debug=True)


def return_common_params():
    port = demisto.params().get('longRunningPort')
    inc = demisto.incident()
    ic = get_integration_context()
    uuid_ret = str(uuid.uuid4())
    ext_url = demisto.params().get('xsoar-external-url').rstrip('/')
    integration_name = demisto.integrationInstance()
    return port, inc, ic, uuid_ret, ext_url, integration_name


def run_setup_simple_action():
    port, inc, integration_context, entry_uuid, xsoar_external_url, integration_instance_name = return_common_params()
    user_emails = demisto.args().get('emailaddresses').split(',')
    user_string = demisto.args().get('userstring', '')
    input_list = demisto.args().get('actions').split(',')
    htmltemplate = demisto.args().get('htmltemplate')
    xsoar_proxy = demisto.args().get('xsoarproxy')
    link_tracker = {}

    for email in user_emails:
        html_dict = {}
        link_uuid = str(uuid.uuid4())
        partial_link = f'{xsoar_external_url}/instance/execute/{integration_instance_name}/process/{entry_uuid}/{link_uuid}/'
        partial_link_port = f'{xsoar_external_url}:{port}/instance/execute/{integration_instance_name}/process/{entry_uuid}/{link_uuid}/'  # noqa: E501
        temp_link_tracker = {"response": "", "response_received": False, "emailaddress": email}

        for ind, action in enumerate(input_list):
            marker = ind + 1
            if xsoar_proxy == 'true':
                temp_link_tracker[f"action_{action}_url"] = partial_link + action
                html_dict[f"action{marker}"] = partial_link + action
            else:
                temp_link_tracker[f"action_{action}_url"] = partial_link_port + action
                html_dict[f"action{marker}"] = partial_link_port + action
        temp_link_tracker['htmlemail'] = Template(htmltemplate).substitute(**html_dict)
        link_tracker[link_uuid] = temp_link_tracker

    integration_context[entry_uuid] = {"type": "simple_action", "inc_id": inc['id'], "input_list": input_list,
                                       "link_tracker": link_tracker, "job_uuid": entry_uuid, "completed": False,
                                       "user_string": user_string
                                       }
    set_integration_context(integration_context)
    to_return = CommandResults(outputs_prefix='WS-ActionDetails(val.job_uuid==obj.job_uuid)',
                               outputs=integration_context[entry_uuid])
    return_results(to_return)


def run_setup_post_action():
    port, inc, integration_context, entry_uuid, xsoar_external_url, integration_instance_name = return_common_params()
    user_emails = demisto.args().get('emailaddresses').split(',')
    user_string = demisto.args().get('userstring', '')
    htmltemplate = demisto.args().get('htmltemplate')
    xsoar_proxy = demisto.args().get('xsoarproxy')

    link_tracker = {}
    for ind, email in enumerate(user_emails):
        html_dict = {}
        link_uuid = str(uuid.uuid4())
        partial_link = f'{xsoar_external_url}/instance/execute/{integration_instance_name}/processform/{entry_uuid}/{link_uuid}/'
        partial_link_port = f'{xsoar_external_url}:{port}/instance/execute/{integration_instance_name}/processform/{entry_uuid}/{link_uuid}/'  # noqa: E501

        if xsoar_proxy == "true":
            action_url = partial_link
        else:
            action_url = partial_link_port
        html_dict["action1"] = action_url
        temp_link_tracker = {"response": "", "response_received": False, "emailaddress": email, "action_url": action_url,
                             "htmlemail": Template(htmltemplate).substitute(**html_dict)}
        link_tracker[link_uuid] = temp_link_tracker

    integration_context[entry_uuid] = {"type": "post_action", "inc_id": inc['id'],
                                       "link_tracker": link_tracker, "job_uuid": entry_uuid, "completed": False,
                                       "user_string": user_string
                                       }
    set_integration_context(integration_context)
    to_return = CommandResults(outputs_prefix='WS-ActionDetails(val.job_uuid==obj.job_uuid)',
                               outputs=integration_context[entry_uuid])
    return_results(to_return)


def run_clear_integration_cache():
    set_integration_context({})
    return_results("cleared backend cache")


def run_show_integration_cache():
    ic = get_integration_context()
    return_results(json.dumps(ic))


def remove_action_internal(uuid):
    integration_context = get_integration_context()
    integration_context.pop(uuid)
    set_integration_context(integration_context)


def run_remove_action():
    uuid = demisto.args().get('uuid')
    lookup, data = validate_uuid(uuid)
    if lookup:
        remove_action_internal(uuid)
    else:
        return_results(data)


def validate_uuid(uuid):
    integration_context = get_integration_context()
    try:
        data = integration_context[uuid]
        return True, data
    except KeyError:
        return False, "Action lookup failed; please check the UUID"


def run_get_action_status():
    uuid = demisto.args().get('uuid')
    lookup, data = validate_uuid(uuid)
    if lookup:
        input_get_req = data.get("input_list", "")
        output_to_ret = {"job_uuid": data["job_uuid"], "incident_id": data["inc_id"], "user_string": data["user_string"],
                         "completed": data["completed"], "input_list": input_get_req}
        link_tracker = data["link_tracker"]
        link_tracker_list = []
        for key, value in link_tracker.items():
            link_tracker_list.append({"link_uuid": key, "email": value["emailaddress"],
                                      "response": value["response"], "response_received": value["response_received"],
                                      "emailhtml": value["htmlemail"]})
        output_to_ret["link_tracker"] = link_tracker_list
        to_return = CommandResults(outputs_prefix='WS-ActionStatus(val.job_uuid==obj.job_uuid)',
                                   readable_output="fetching current status", outputs=output_to_ret)
        return_results(to_return)
    else:
        return_results(data)


def run_set_job_complete(uuid):
    lookup, data = validate_uuid(uuid)
    if lookup:
        ic = get_integration_context()
        data["completed"] = True
        ic[uuid] = data
        set_integration_context(ic)
        return_results("Job successfully marked as Complete")
    else:
        return_results(data)


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
            run_setup_simple_action()
        elif command == 'xsoar-ws-clear-cache':
            run_clear_integration_cache()
        elif command == 'xsoar-ws-show-cache':
            run_show_integration_cache()
        elif command == 'xsoar-ws-get-action-status':
            run_get_action_status()
        elif command == 'xsoar-ws-remove-action':
            run_remove_action()
        elif command == 'xsoar-ws-set-job-complete':
            job_uuid = demisto.args().get('uuid')
            run_set_job_complete(job_uuid)
        elif command == 'xsoar-ws-setup-form-submission':
            run_setup_post_action()
        else:
            return_error('Command not found')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
