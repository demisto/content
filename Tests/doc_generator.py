import yaml
import sys

reload(sys)
sys.setdefaultencoding('utf-8')


def return_error(error):
    print 'DOCUMENT GENERATION PROCESS FAILED'
    print error
    sys.exit(1)


# load the integration yml file
path = sys.argv[1]
yamlFile  = open(path)
data_map = yaml.safe_load(yamlFile)
yamlFile.close()


def add_lines(line):
    output = ''
    last_digit = 0
    for i in range(len(line)):
        if line[i].isdigit():
            if line[i+1] == '.':
                output += line[last_digit:i] + '\n'
                last_digit = i

    output += line[last_digit:len(line)] + '\n'
    return output


def add_error_lines(script_to_scan, script_type):
    res = ''
    if 'python' in script_type:
        error_keys = ['return_error', 'raise ']
    elif 'javascript' in script_type:
        error_keys = ['throw ']
    # Unsupported script type
    else:
        return res
    lines_to_skip = 0
    script_lines = script_to_scan.splitlines()
    for idx in range(len(script_lines)):
        # Skip lines that were already scanned
        if lines_to_skip > 0:
            lines_to_skip -= 1
            continue
        line = script_lines[idx]
        if any(key in line for key in error_keys):
            if '(' in line:
                bracket_open_idx = line.index('(') + 1
                if ')' in line:
                    bracket_close_idx = line.index(')')
                    res += '* ' + line[bracket_open_idx:bracket_close_idx] + '\n'
                # Handle multi line error
                else:
                    res += '*' + ('' if len(line[bracket_open_idx:].lstrip()) < 1 else ' ' + line[bracket_open_idx:] + '\n')
                    while not ')' in script_lines[idx + lines_to_skip + 1]:
                        lines_to_skip += 1
                        line = script_lines[idx + lines_to_skip]
                        res += ' ' + line.lstrip() + '\n'
                    # Adding last line of error
                    lines_to_skip += 1
                    line = script_lines[idx + lines_to_skip]
                    bracket_close_idx = line.index(')')
                    res += line[:bracket_close_idx].lstrip() + '\n'
            else:
                first_matching_error_key = next((key for key in error_keys if key in line), False)
                after_error_key_idx = line.index(first_matching_error_key) + len(first_matching_error_key)
                res += '* ' + line[after_error_key_idx:] + '\n'
    return res


name = data_map['name']
doc = ''


# Overview
doc += '## Overview\n'
doc += '---\n'

doc += 'This integration was integrated and tested with version xx of ' + name + '\n'


# Playbooks
doc += "## {} Playbook\n".format(name)
doc += '---\n'


# Use-cases
doc += '## Use cases\n'
doc += '---\n'


# Setup integration to work with Demisto
doc += '\n## Configure ' + name + ' on Demisto\n'
doc += '---\n'

# Setup integration on Demisto
doc += '''
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for ''' + name + '''.
3. Click __Add instance__ to create and configure a new integration instance.
You should configure the following settings:
  * __Name__: a textual name for the integration instance.
'''
j=2
for i in range(len(data_map['configuration'])):
    if (data_map['configuration'][i]['display']):
        doc += '  * __' + data_map['configuration'][i]['display'] + '__\n'
    else:
        doc += '  * __' + data_map['configuration'][i]['name'] + '__\n'
    j += 1
doc += '4. Click __Test__ to validate the URLs, token, and connection.' +'\n'
# Fetched incidents data
doc += '\n## Fetched Incidents Data\n'
doc += '---\n'

# Commands
doc += '\n## Commands\n'
doc += '---\n'
doc += 'You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.\n'
doc += 'After you successfully execute a command, a DBot message appears in the War Room with the command details.\n'
for i in range(len(data_map['script']['commands'])):
    doc += str(i+1) + '. ' + data_map['script']['commands'][i]['name'] + '\n'
for i in range(len(data_map['script']['commands'])):
    try:
        doc += '### ' + data_map['script']['commands'][i]['name'] + '\n'
        doc += '---\n'
        doc += str(data_map['script']['commands'][i].get('description', " ")) + '\n'
        doc += '##### Base Command\n'
        doc += '`' + data_map['script']['commands'][i]['name'] + '`' + '\n'
        # Inputs
        doc += '##### Input\n'
        doc += '| **Argument Name** | **Description** | **Required** |\n'
        doc += '| --- | --- | --- |\n'
        if len(data_map['script']['commands'][i]['arguments']) != 0:
            for j in range(len(data_map['script']['commands'][i]['arguments'])):
                doc += '| ' + data_map['script']['commands'][i]['arguments'][j]['name'] + ' | '
                if not (data_map['script']['commands'][i]['arguments'][j].get('description', False)):
                    return_error("Error! You are missing description in input " + data_map['script']['commands'][i]['arguments'][j]['name'] +\
                    " of command " + data_map['script']['commands'][i]['name'])
                    sys.exit(0)
                doc += data_map['script']['commands'][i]['arguments'][j]['description'] + ' | '
                doc += str(data_map['script']['commands'][i]['arguments'][j].get('required', 'False')) + ' | \n'
        else:
            doc += '-\n'
        # Context output
        doc += '##### Context Output\n'
        if 'outputs' in data_map['script']['commands'][i]:
            doc += '| **Path** | **Type** | **Description** |\n'
            doc += '| --- | --- | --- |\n'
            for k in range(len(data_map['script']['commands'][i]['outputs'])):
                doc += '| ' + data_map['script']['commands'][i]['outputs'][k]['contextPath'] + ' | '
                doc += str(data_map['script']['commands'][i]['outputs'][k].get('type', 'unknown')) + ' | '
                if not (data_map['script']['commands'][i]['outputs'][k].get('description', False)):
                    return_error("Error! You are missing description in output " + data_map['script']['commands'][i]['outputs'][j]['name'] + \
                    " of command " + data_map['script']['commands'][i]['name'])
                    sys.exit(0)
                doc += data_map['script']['commands'][i]['outputs'][k]['description'] + ' | \n'
        else:
            doc += 'There is no context output for this command.\n'

        # Raw output:
        doc += '##### Command Example\n'
        doc += '##### Context Example\n'
        doc += '##### Human Readable Output\n'
        doc += '\n'
    except Exception as e:
        return_error("Error encountered in the processing of command {} error was missing a {}. Please check your command inputs and outputs".format(data_map['script']['commands'][i]['name'], str(e)))
        sys.exit(0)
# Additional info
doc += '\n## Additional information:\n'

# Known limitations
doc += '\n## Known limitations:'

# Troubleshooting
doc += '\n## Troubleshooting:\n'

# Possible Errors
# if 'True' == demisto.args()['withErrors']:
#     doc += '\n## Possible Errors (DO NOT PUBLISH ON ZENDESK):\n'
#     doc += add_error_lines(data_map['script']['script'], data_map['script']['type'])

filename = name + '-documantation.txt'

# save file by default at same path unless the second arg provided
if len(sys.argv) > 2:
    save_path = sys.argv[2]

with open(filename, 'w') as f:
    f.write(doc)
