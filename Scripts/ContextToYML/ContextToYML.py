from CommonServerPython import *
import demistomock as demisto

import yaml

"""
This script parse a Context output into yml formatted file with the context path of each field.
For example:

{
    "id":12131,
    "description":"desc",
    "summary":"do-not-delete",
    "created":"2019-03-25T16:13:13.188+0200",
    "issuetype":{
        "id":10004,
        "name":"Bug"
    },
    "project":{
        "id":10001,
        "key":"SOC",
        "projectTypeKey":"software"
    },
    "status":{
        "id":10003,
            "StatusCategory":{
                "key":"new",
                "colorName":"blue-gray",
                "name":"To Do"
        }
    }
}

==>

arguments: []
name: integration-command
outputs:
- contextPath: Demisto.Id
  description: ''
  type: Number
- contextPath: Demisto.Description
  description: ''
  type: String
- contextPath: Demisto.Summary
  description: ''
  type: String
- contextPath: Demisto.Created
  description: ''
  type: String
- contextPath: Demisto.Issuetype.Id
  description: ''
  type: Number
- contextPath: Demisto.Issuetype.Name
  description: ''
  type: String
- contextPath: Demisto.Project.Id
  description: ''
  type: Number
- contextPath: Demisto.Project.Key
  description: ''
  type: String
- contextPath: Demisto.Project.ProjectTypeKey
  description: ''
  type: String
- contextPath: Demisto.Status.Id
  description: ''
  type: Number
- contextPath: Demisto.Status.StatusCategory.Key
  description: ''
  type: String
- contextPath: Demisto.Status.StatusCategory.Colorname
  description: ''
  type: String
- contextPath: Demisto.Status.StatusCategory.Name
  description: ''
  type: String
"""

VERBOSE = demisto.getArg('verbose') == 'true'
CAMELIZE = demisto.getArg('camelize') == 'true'


def flatten_json(nested_json):
    out = {}

    def flatten(x, name=''):
        # capitalize first letter in each key
        try:
            name = name[0].upper() + name[1:] if CAMELIZE else name
        except IndexError:
            name = name.title() if CAMELIZE else name

        if isinstance(x, dict):
            for a in x:
                flatten(x[a], name + a + '.')
        elif isinstance(x, list):
            for a in x:
                flatten(a, name[:-1] + '.')
        else:
            out[name.rstrip('.')] = x

    flatten(nested_json)
    return out


def jsonise(context_key, value):
    return {'contextPath': context_key, 'description': '', 'type': determine_type(value)}


def determine_type(val):
    return 'Boolean' if isinstance(val, bool) else 'Number' if isinstance(
        val, (int, float)) else 'String' if isinstance(val, str) else 'Unknown'


def parse_json(data, command_name, base_path):
    data = json.loads(data)
    flattened_data = flatten_json(data)
    if base_path:
        flattened_data = {f'{base_path.title()}.{key}': value for key, value in flattened_data.items()}

    arg_json = [jsonise(key, value) for key, value in flattened_data.items()]

    if VERBOSE:
        print(f'JSON before converting to YAML: {arg_json}')

    yaml_output = yaml.safe_dump(
        {
            'name': command_name.lstrip('!'),
            'arguments': [],
            'outputs': arg_json
        },
        default_flow_style=False
    )
    return yaml_output


def main():
    command_name = demisto.args().get("command_name", '')
    base_path = demisto.args().get("base_path", '')
    entry_id = demisto.getArg("json_file_entry_id")
    json_file_as_text = demisto.getArg("json_file_as_text")

    yaml_output = ''
    if json_file_as_text:
        if not base_path:
            demisto.results('please enter base path for context output')

        yaml_output = parse_json(json_file_as_text, command_name, base_path)

    if entry_id:
        if not base_path:
            demisto.results('please enter base path for context output')

        json_file_path = demisto.getFilePath(entry_id)['path']
        with open(json_file_path, 'r') as json_file:
            yaml_output = parse_json(json_file, command_name, base_path)

    filename = f'{command_name}-outputs.yml'
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': yaml_output,
        'HumanReadable': yaml_output,
    })
    demisto.results(fileResult(filename, yaml_output, file_type=entryTypes['entryInfoFile']))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
