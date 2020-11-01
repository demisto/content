from CommonServerPython import *
from CommonServerUserPython import *
import json
import os
import sys

from cStringIO import StringIO

handle_proxy(demisto.params().get('proxy'))

response = ''

# disable python from generating a .pyc file
sys.dont_write_bytecode = True

# change me to the path of pytan
pytan_loc = "/pytan-2.2.2"
pytan_static_path = os.path.join(os.path.expanduser(pytan_loc), 'lib')

# Determine our script name, script dir
my_file = os.path.abspath(sys.argv[0])
my_dir = os.path.dirname(my_file)

# try to automatically determine the pytan lib directory by assuming it is in '../../lib/'
parent_dir = os.path.dirname(my_dir)
pytan_root_dir = os.path.dirname(parent_dir)
lib_dir = os.path.join(pytan_root_dir, 'lib')

# add pytan_loc and lib_dir to the PYTHONPATH variable
path_adds = [lib_dir, pytan_static_path]
[sys.path.append(aa) for aa in path_adds if aa not in sys.path]  # type: ignore

try:
    import pytan
    import pytan.binsupport
    import taniumpy
except Exception:
    raise


def raw_response_to_json(raw_json):
    result = []
    for row_dict in raw_json:
        row_key = row_dict.keys()[0]
        parsed_row_dict = {}
        for cell in row_dict[row_key]:
            column_name = cell.get('column.display_name')
            cell_value = cell.get('column.values')
            cell_value_without_none = []

            for value in cell_value:
                if value is not None:
                    cell_value_without_none.append(value)

            if len(cell_value_without_none) > 0:
                cell_value = '\n'.join(cell_value_without_none)

            else:
                cell_value = None

            parsed_row_dict[column_name] = cell_value

        result.append(parsed_row_dict)

    return result


def parseToJson(handler, response):
    LOG("exporting tanium response")
    export_kwargs = {}
    export_kwargs['obj'] = response
    export_kwargs['export_format'] = 'json'
    out = handler.export_obj(**export_kwargs)
    return json.loads(out)


def create_error_entry(contents):
    return {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['error'],
        'Contents': "Error - " + contents
    }


def create_entry(header, table, context={}, headers=None):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': table,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(header, table,
                                         headers) if table else '### ' + header + '\nNo results were found',
        'EntryContext': context
    }


def filter_list(lst, keys):
    res = []
    for i in range(len(lst)):
        tmp = {}
        for key in keys:
            tmp[key] = lst[i].get(key)
        res.append(tmp)
    return res


def get_handler():
    handler_args = {}

    handler_args['username'] = demisto.params().get('credentials', {}).get('identifier')
    handler_args['password'] = demisto.params().get('credentials', {}).get('password')
    handler_args['host'] = demisto.params().get('host')
    handler_args['port'] = demisto.params().get('port')

    handler_args['loglevel'] = 1
    handler_args['debugformat'] = False
    handler_args['record_all_requests'] = True

    return pytan.Handler(**handler_args)


def get_all_objects(handler, objtype):
    LOG("getting all tanium objects of type %s" % objtype)
    kwargs = {}
    kwargs["objtype"] = objtype
    response = handler.get_all(**kwargs)
    return parseToJson(handler, response)


def get_all_objects_with_entry(handler, objtype):
    response = get_all_objects(handler, unicode(objtype))
    parsed = response[objtype]
    return create_entry('Tanium ' + objtype + 's', parsed)


def get_all_sensors(handler):
    response = get_all_objects(handler, u'sensor')
    parsed = response.get('sensor')
    return create_entry('Tanium Sensors', parsed, {'Tanium.Sensors': parsed})


def get_all_saved_actions(handler):
    response = get_all_objects(handler, u'saved_action')
    parsed = response.get('saved_action')
    return create_entry('Tanium Saved Actions', parsed, {'Tanium.SavedActions': parsed},
                        ['id', 'name', 'creation_time', 'action_group_id', 'approved_flag'])


def getAllPendingActions(handler):
    response = get_all_objects(handler, u'saved_action')
    parsed = response.get('saved_action')
    filterNonPending = filter(lambda x: x['approved_flag'] == 0, parsed)
    return create_entry('Tanium Pending Actions', filterNonPending, {'Tanium.PendingActions': filterNonPending},
                        ['id', 'name', 'creation_time', 'action_group_id', 'approved_flag'])


def getAllPackages(handler):
    response = get_all_objects(handler, u'package')
    parsed = response.get('package_spec')
    return create_entry('Tanium Packages', parsed, {'Tanium.Packages': parsed},
                        ['id', 'name', 'creation_time', 'command', 'last_modified_by'])


def get_all_saved_questions(handler):
    response = get_all_objects(handler, u'saved_question')
    parsed = response.get('saved_question')
    return create_entry('Tanium Saved Questions', parsed, {'Tanium.SavedQuestions': parsed},
                        ['query_text', 'name', 'id'])


def get_object(handler, objtype, name=None, id=None):
    LOG("getting Tanium %s - %s" % (objtype, name if name is not None else id))
    kwargs = {}
    kwargs["objtype"] = objtype
    kwargs["id"] = id
    kwargs["name"] = name

    response = handler.get(**kwargs)
    return parseToJson(handler, response)


def parameter_table_builder(data, header, object_type):
    if not data.get('parameter_definition'):
        return 'No arguments needed for this ' + object_type
    param_data = json.loads(data['parameter_definition']).get('parameters', [])
    parsed_params = []
    parsed_param = {}
    for param in param_data:
        parsed_param['Description'] = param.get('helpString', 'No description')
        parsed_param['Name'] = param.get('label', 'No argument name')
        parsed_param['Values'] = ','.join(param['values']) if param.get('values') else 'Any value'
        parsed_param['Key'] = param.get('key', 'No key')
        parsed_param['Type'] = param['parameterType'].split('::')[-1] if param.get(
            'parameterType') else 'Type not specified'
        parsed_params.append(parsed_param)
        parsed_param = {}
    data['parameters'] = parsed_params
    del data['parameter_definition']
    return tableToMarkdown(header, parsed_params, ['Key', 'Name', 'Values', 'Description', 'Type'])


def get_sensor_variable(parsed):
    if len(parsed) > 0 and parsed[0].get('command'):
        command = parsed[0].get('command')
        if command:
            idx1 = command.find("||")
            if idx1 > -1:
                idx2 = command.find("||", idx1 + 2)
                if idx2 > -1:
                    return command[idx1:idx2 + 2]
    return None


def get_package(handler):
    response = get_object(handler, u'package', demisto.args().get('name'), demisto.args().get('id'))
    parsed = response.get('package_spec')
    sensor_var = get_sensor_variable(parsed)
    res = parsed[0]
    res['sensor_variable'] = sensor_var
    parameters = parameter_table_builder(res, 'Package Arguments Details', 'package')
    final_result = create_entry(
        'Tanium Package',
        res,
        {'Tanium.Packages(val.id && val.id == obj.id)': filter_list([res], ['name', 'id', 'display_name', 'command',
                                                                            'command_timeout', 'deleted_flag', 'files',
                                                                            'parameters', 'sensor_variable'])},
        ['id', 'name', 'creation_time', 'command', 'last_modified_by']
    )
    final_result['HumanReadable'] += parameters
    if sensor_var is not None:
        final_result['HumanReadable'] += '\n### Sensor Variables Type\n' + sensor_var
    return final_result


def get_saved_question(handler):
    response = get_object(handler, u'saved_question', demisto.args().get('name'), demisto.args().get('id'))
    parsed = response.get('saved_question')
    return create_entry(
        'Tanium Saved Question',
        parsed,
        {'Tanium.SavedQuestions(val.id && val.id == obj.id)': filter_list(parsed,
                                                                          ['query_text', 'mod_time', 'user', 'name',
                                                                           'expire_seconds', 'id', 'issue_seconds'])},
        ['query_text', 'name', 'id']
    )


def get_sensor(handler):
    response = get_object(handler, u'sensor', demisto.args().get('name'), demisto.args().get('id'))
    parsed = response.get('sensor', None)
    parameters = parameter_table_builder(parsed[0], 'Sensor Parameters Details', 'sensor')
    final_result = create_entry(
        'Tanium Sensor - ' + demisto.args()['name'],
        parsed,
        {'Tanium.Sensors(val.id && val.id == obj.id)': filter_list(parsed,
                                                                   ['id', 'name', 'max_age_seconds', 'description',
                                                                    'parameters'])},
        ['id', 'name', 'category', 'description'])
    final_result['HumanReadable'] += '\n' + parameters
    return final_result


def get_action(handler):
    response = get_object(handler, u'action', demisto.args().get('name'), demisto.args().get('id'))
    parsed = response.get('action', None)
    if 'saved_action' in parsed[0]:
        parsed[0]['saved_action_id'] = parsed[0]['saved_action']['id']
        del parsed[0]['saved_action']

    return create_entry(
        'Tanium Action - ' + parsed[0]['name'],
        parsed,
        {'Tanium.Actions(val.id && val.id == obj.id)': filter_list(parsed,
                                                                   ['name', 'id', 'status', 'start_time', 'approver',
                                                                    'creation_time', 'package_spec'])},
        ['id', 'name', 'status', 'saved_action_id', 'stopped_flag'])


def handle_cgs(handler, obj, kwargs):
    """Example PreAddAction callback that modifies the target_group of an Action if computer group names are supplied.
    callbacks = {}
    callbacks["PreAddAction"] = handle_cgs
    deploy_action(package="blah", cg_names=["ip has 192.168", "has tanium app"], action_filters=["Computer Name, that
     contains:a"], callbacks=callbacks)
    """
    cgs = kwargs.get("cg_names", [])
    LOG("handling cgs %s" % cgs)
    cg_objs = [handler.get("group", name=x)[0] for x in cgs]
    cg_listobj = taniumpy.GroupList()
    [cg_listobj.append(x) for x in cg_objs]

    if cg_objs:
        tg_obj = taniumpy.Group()
        tg_obj.sub_groups = cg_listobj
        tg_obj.and_flag = 0
        if obj.target_group is not None:
            tg_obj.sub_groups.append(obj.target_group)
        obj.target_group = tg_obj
    return obj


def parse_deploy_action_raw_resp(handler, response):
    saved_action_object = response.get('saved_action_object')
    action_object = response.get('action_object')
    package_object = response.get('package_object')

    return {
        'saved_action_object': parseToJson(handler, saved_action_object),
        'action_object': parseToJson(handler, action_object),
        'package_object': parseToJson(handler, package_object)
    }


def deploy_action(handler):
    kwargs = {}
    kwargs["run"] = True

    for key, value in demisto.args().items():
        kwargs[key] = value

    kwargs["get_results"] = True if str(kwargs.get('get_results', '')).lower() == 'true' else False

    callbacks = {}
    callbacks['PreAddAction'] = handle_cgs
    kwargs['callbacks'] = callbacks  # type: ignore
    kwargs['action_options'] = ['or']  # type: ignore
    if demisto.get(demisto.args(), 'action_options'):
        kwargs['action_options'] = demisto.args()['action_options'].split(',')
    if demisto.get(demisto.args(), 'action_filters'):
        kwargs['action_filters'] = demisto.args()['action_filters'].split(';')
    if demisto.get(demisto.args(), 'action_filters_groups'):
        kwargs['cg_names'] = demisto.args()['action_filters_groups'].split(',')

    # Building the package query
    package = demisto.args()['package']
    package_with_args = [package]

    formatted_args = ''
    if demisto.args().get('package_args'):
        package_args = demisto.args().get('package_args', '').split(",")
        for i in range(0, len(package_args)):
            formatted_args = formatted_args + '$' + str(i + 1) + '=' + package_args[i] + ','
        formatted_args = formatted_args[:-1]

    replace_str = get_sensor_variable(get_object(handler, u'package', package).get('package_spec'))
    sensor_var = demisto.args().get('sensor_variables')

    if replace_str is None and sensor_var:
        return create_error_entry("Package \"" + package + "\" does not have a sensor variable.")
    if replace_str and sensor_var is None:
        return create_error_entry("Package \"" + package + "\" requires a sensor variable.")

    if sensor_var:
        sensor_vars = demisto.args().get('sensor_variables', '').split(";")
        package_with_args = []
        if formatted_args != '':
            formatted_args += ','
        for var in sensor_vars:
            package_with_args.append(package + '{' + formatted_args + replace_str + '=' + var + '}')

    elif formatted_args != '':
        package_with_args = [package + '{' + formatted_args + '}']

    response = []
    for pack in package_with_args:
        kwargs['package'] = pack
        LOG("deploying Tanium package %s" % pack)
        response.append(handler.deploy_action(**kwargs))

    ec = {  # type: ignore
        'Tanium.SavedActions(val.Id && val.Id == obj.Id)': [],
        'Tanium.Actions(val.id && val.id == obj.id)': []
    }
    contents = []
    tbl = []

    for res in response:
        ec['Tanium.SavedActions(val.Id && val.Id == obj.Id)'].append({
            'Name': res['saved_action_object'].name,
            'Id': res['saved_action_object'].id
        })
        parsed = parse_deploy_action_raw_resp(handler, res)
        ec['Tanium.Actions(val.id && val.id == obj.id)'] += filter_list([parsed['action_object']],
                                                                        ['name', 'id', 'status', 'start_time',
                                                                         'approver', 'creation_time', 'package_spec'])
        contents.append(parsed)
        tbl.append({
            'Action ID': parsed['action_object']['id'],
            'Saved Action ID': parsed['saved_action_object']['id'],
            'Name': parsed['action_object']['name'],
            'Package Name': parsed['package_object']['name'],
            'Command': parsed['package_object']['command']
        })

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Tanium Deployed Actions', tbl) if tbl else 'No results were found',
        'EntryContext': ec
    }


def approveSavedAction(handler, action_id, saved_action_id):
    LOG("approving saved action with id %s %s" % (action_id, saved_action_id))
    kwargs = {}
    if not saved_action_id and not action_id:
        raise Exception('Missing action ID')
    if not saved_action_id:
        action = get_object(handler, u'action', id=action_id)
        parsed = action.get('action', None)
        saved_action_id = parsed[0]['saved_action']['id']
    kwargs['id'] = saved_action_id
    response = handler.approve_saved_action(**kwargs)
    parsed = {'Id': response.id, 'Name': response.name, 'ApprovedFlag': response.approved_flag}
    final_result = create_entry('Action Approval', [parsed], {'Tanium.ActionApproval': parsed})
    return final_result


def format_context(res):
    """Reformat the response's multi-lined cells to look better in the context

    Args:
        res (list): a list of dictionaries formatted from the Tanium answer

    Returns:
        list. A list of dictionaries where multi-lined cells have spaces instead of line drops.
    """
    context = []
    for element in res:
        context.append({key: value.split('\n') if value and '\n' in value else value
                        for (key, value) in element.items()})

    return context


def askQuestion(handler, kwargs):
    response = handler.ask(**kwargs)

    if isinstance(response, str):
        return response

    query_text = response['question_object'].query_text
    if response.get('question_results'):
        export_kwargs = {}
        export_kwargs['obj'] = response['question_results']
        export_kwargs['export_format'] = 'json'
        LOG("exporting tanium question response")
        out = handler.export_obj(**export_kwargs)
        if out:
            result = raw_response_to_json(json.loads(out))

        else:
            result = []

        ec = {'Tanium.QuestionResults': format_context(result)}
        return create_entry(
            'Result for parsed query - %s' % (query_text,),
            result,
            ec)
    else:
        return 'Parsed query - %s\nNo results were found' % (query_text,)


def get_parse_query_options(handler, question):
    LOG("parsing query options")
    parse_job_results = handler.parse_query(question)
    jsonable = parse_job_results.to_jsonable()

    ans = jsonable["parse_result_group"]
    res = []
    i = 0
    while i < len(ans):
        res.append({"index": i + 1, "question": ans[i]["question_text"]})
        i = i + 1
    return create_entry('Tanium Questions', res, {}, ['index', 'question'])


def get_ask_manual_help():
    desc = '# Tanium Ask Manual Question - Help\n' + \
           'The _tn-ask-manual-question_ command corresponds directly with the Tanium Question Builder.\n' + \
           'Each command argument can be mapped to a field in the Tanium Question Builder.\n' + \
           '## Sensors\n---\n' + \
           'The _sensors_ argument correlates with the **"Get all ____ from..."** part of a the Tanium Question.\n' + \
           'All sensor types share the same filters and sensor options, but each sensor has its own parameters.\n' + \
           '\n' + \
           '**Example** (simple sensor list):\n' + \
           '`!tn-ask-manual-question sensors="Computer Name;IP Address"`\n' + \
           '### Sensor filters\n' + \
           'You can only apply a single filter to a sensor, and should be passed using this format:\n' + \
           '_<sensor1>,that <filter type>:<filter value>;<sensor2>,that <filter type>:<filter value>_\n' + \
           '\n' + \
           '**Example #1** (2 sensors, 2 filters):\n`!tn-ask-manual-question sensors="Computer Name,that starts with:' \
           'D;IP Address,that does not contain:192"`\n**Example #2** (2 sensors, 1 filter):\n' + \
           '`!tn-ask-manual-question sensors="Computer Name,that starts with:D;IP Address"`\n' + \
           '### Sensor parameters\n' + \
           'Each sensor has its own unique parameters. ' \
           'To get a complete list of sensor parameters, run the _!tn-get-sensor_ command.\n' + \
           'Parameters are passed in curly brackets, after the sensor name, and before the filter.\n' + \
           '**Example** (1 sensor, 1 filter, 1 parameter):\n' + \
           '`!tn-ask-manual-question sensors=' \
           '"Index Query File Exists{fileMD5Hash=4F83C01E8F7507D23C67AB085BF79E97},that contains:yes"`\n' + \
           '### Sensor options\n' + \
           'All sensors have the same options: _ignore_case_, _match_case_, _match_any_value_, _match_all_values_, ' \
           '_max_data_age_, _value_type_\nOptions are passed directly after filters.\n\n' \
           '**Example** (1 sensor, 1 filter, 1 parameter):\n' + \
           '`!tn-ask-manual-question sensors="Index Query File Exists{fileMD5Hash=4F83C01E8F7507D23C67AB085BF79E97},' \
           'that contains:yes,opt:match_all_values, opt:ignore_case, opt:max_data_age:3600"`\n' + \
           '## Question Filters\n---\n' + \
           'The _question_filters_ argument is a semicolon-separated list of sensors, with filters and parameters, ' \
           'that correlates to the **"... from all computers with ___"** part of a the Tanium Question.\n' + \
           'Question filters can have an ***and*** or an ***or*** relation. ' \
           'You set the relation by using the _question_options_ argument.\n\n' + \
           '**Example** (2 question filters):\n`!tn-ask-manual-question sensors="Computer Name" question_filters=' \
           '"Index Query File Exists{fileMD5Hash=4F83C01E8F7507D23C67AB085BF79E97},that contains:yes;' \
           'Index Query File Exists{fileMD5Hash=4F83C01E8F7507D23C67AB085BF79E98},that contains:yes"`\n\n' + \
           '## Question Options\n---\n' + \
           'Question options are a semicolon-separated list of options that apply to the entire question. They are ' \
           'generally used to define the relation of the different filter statements.\n' + \
           '**Example** (1 question option):\n`!tn-ask-manual-question sensors="Computer Name" question_options="or" ' \
           'question_filters="Index Query File Exists{' \
           'fileMD5Hash=4F83C01E8F7507D23C67AB085BF79E97},that contains:yes"`\n'
    return {
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': desc,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': desc
    }


def ask_manual_question(handler, args):
    if args.get('help') == 'True':
        return get_ask_manual_help()

    kwargs = {}
    kwargs["qtype"] = u'manual'
    kwargs["sensors_help"] = True if args.get('sensors_help') == 'True' else False  # type: ignore
    kwargs["filters_help"] = True if args.get('filters_help') == 'True' else False  # type: ignore
    kwargs["options_help"] = True if args.get('options_help') == 'True' else False  # type: ignore

    if kwargs["filters_help"] or kwargs["sensors_help"] or kwargs["options_help"]:
        try:
            response = handler.ask(**kwargs)
            # should always throw an exception
            return response
        except Exception as ex:
            return str(ex)

    kwargs["question_options"] = args.get('question_options', '').split(';') if args.get('question_options',
                                                                                         '') != '' else None
    kwargs["question_filters"] = args.get('question_filters', '').split(';') if args.get('question_filters',
                                                                                         '') != '' else None
    kwargs["sensors"] = args.get('sensors', '').split(';') if args.get('sensors', '') != '' else None
    kwargs["polling_secs"] = int(args.get('polling_secs', '5'))  # type: ignore
    kwargs["complete_pct"] = int(args.get('complete_pct', '99'))  # type: ignore

    LOG("asking Tanium question")
    return askQuestion(handler, kwargs)


def ask_parsed_question(handler, question, index):
    kwargs = {
        'picker': int(index),
        'question_text': question,
        'qtype': u'parsed',
        'get_results': True
    }

    LOG("asking Tanium question %s" % (question))
    return askQuestion(handler, kwargs)


def create_package(handler):
    kwargs = {}
    dArgs = demisto.args()
    for key, value in dArgs.items():
        kwargs[key] = value
    if demisto.get(dArgs, 'file_urls'):
        kwargs['file_urls'] = dArgs['file_urls'].split(",")
    LOG("creating Tanium package")
    response = handler.create_package(**kwargs)
    parsed = parseToJson(handler, response)
    final_result = create_entry('Tanium Package', [parsed], {'Tanium.Packages': parsed},
                                ['id', 'name', 'creation_time', 'command'])
    return final_result


def restore_sout_and_exit(final_result):
    sys.stdout = sout
    LOG.print_log()
    demisto.results(final_result)
    # kill this thread and any additional thread in existence in the docker
    os._exit(0)


# Dealing with Broken Pipe issues raised by some commands
sout = sys.stdout
sys.stdout = StringIO()


def main():
    try:
        handler = get_handler()
        LOG("successfully logged into Tanium")
        d_args = demisto.args()

        if demisto.command() == 'test-module':
            test_question = 'get Computer Name from all machines with Computer Name contains "this is a test"'
            final_result = ask_parsed_question(handler, test_question, '1')
            restore_sout_and_exit('ok')
        if demisto.command() == 'tn-get-package':
            final_result = get_package(handler)
        if demisto.command() == 'tn-get-saved-question':
            final_result = get_saved_question(handler)
        if demisto.command() == 'tn-get-object':
            final_result = get_object(handler, unicode(d_args['object_type']), d_args.get('name'), d_args.get('id'))
        if demisto.command() == 'tn-get-all-objects':
            final_result = get_all_objects(handler, unicode(d_args['object_type']))
        if demisto.command() == 'tn-get-all-packages':
            final_result = getAllPackages(handler)
        if demisto.command() == 'tn-get-all-sensors':
            final_result = get_all_sensors(handler)
        if demisto.command() == 'tn-get-all-saved-questions':
            final_result = get_all_saved_questions(handler)
        if demisto.command() == 'tn-get-all-saved-actions':
            final_result = get_all_saved_actions(handler)
        if demisto.command() == 'tn-get-all-pending-actions':
            final_result = getAllPendingActions(handler)
        if demisto.command() == 'tn-deploy-package':
            final_result = deploy_action(handler)
        if demisto.command() == 'tn-ask-system':
            final_result = ask_parsed_question(handler, 'Get Computer Name from all machines with Computer Name matching \"'
                                               + demisto.args()['hostname'] + '\"', '1')
        if demisto.command() == 'tn-ask-question':
            final_result = ask_parsed_question(handler, d_args['question'], d_args.get('index', '1'))
        if demisto.command() == 'tn-create-package':
            final_result = create_package(handler)
        if demisto.command() == 'tn-approve-pending-action':
            final_result = approveSavedAction(handler, d_args.get('id'),
                                              d_args.get('saved_action_id', d_args.get('action_id')))
        if demisto.command() == 'tn-ask-manual-question':
            final_result = ask_manual_question(handler, d_args)
        if demisto.command() == 'tn-parse-query':
            final_result = get_parse_query_options(handler, d_args['question'])
        if demisto.command() == 'tn-get-sensor':
            final_result = get_sensor(handler)
        if demisto.command() == 'tn-get-action':
            final_result = get_action(handler)

    except Exception:
        sys.stdout = sout
        LOG.print_log()
        raise

    restore_sout_and_exit(final_result)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins" or __name__ == "__main__":
    main()
