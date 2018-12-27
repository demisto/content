import yaml
import sys
import re
import os

reload(sys)
sys.setdefaultencoding('utf-8')


def return_error(error):
    print 'DOCUMENT GENERATION PROCESS FAILED'
    print error
    sys.exit(1)


def get_list_of_commands(integration):
    """
    Returns list of commands as a string

    :param integration: integration dictionary - contains all the metadata of the integration
    :return: string of all the commands in the integration
    """
    list_of_commands_str = ''
    for i in range(len(integration['script']['commands'])):
        list_of_commands_str += str(i + 1) + '. ' + integration['script']['commands'][i]['name'] + '\n'

    return list_of_commands_str


def get_all_commands_details_string(integration):
    """
    Return all integration commands details. Inputs, outputs, descriptions, etc

    :param integration: integration dictionary - contains all the metadata of the integration
    :return: string of all the commands details in the integration
    """
    commands_string = ''
    for i in range(len(integration['script']['commands'])):
        try:
            commands_string += '### ' + integration['script']['commands'][i]['name'] + '\n'
            commands_string += '---\n'
            commands_string += str(integration['script']['commands'][i].get('description', " ")) + '\n'
            commands_string += '##### Base Command\n'
            commands_string += '`' + integration['script']['commands'][i]['name'] + '`' + '\n'
            # Inputs
            commands_string += '##### Input\n'
            commands_string += '| **Argument Name** | **Description** | **Required** |\n'
            commands_string += '| --- | --- | --- |\n'
            if len(integration['script']['commands'][i]['arguments']) != 0:
                for j in range(len(integration['script']['commands'][i]['arguments'])):
                    commands_string += '| ' + integration['script']['commands'][i]['arguments'][j]['name'] + ' | '
                    if not (integration['script']['commands'][i]['arguments'][j].get('description', False)):
                        return_error("Error! You are missing description in input " + integration['script']['commands'][i]['arguments'][j]['name'] +\
                        " of command " + integration['script']['commands'][i]['name'])
                        sys.exit(0)
                        commands_string += integration['script']['commands'][i]['arguments'][j]['description'] + ' | '
                        commands_string += str(integration['script']['commands'][i]['arguments'][j].get('required', 'False')) + ' | \n'
            else:
                commands_string += '-\n'

            # Context output
            commands_string += '##### Context Output\n'
            if 'outputs' in integration['script']['commands'][i]:
                commands_string += '| **Path** | **Type** | **Description** |\n'
                commands_string += '| --- | --- | --- |\n'
                for k in range(len(integration['script']['commands'][i]['outputs'])):
                    commands_string += '| ' + integration['script']['commands'][i]['outputs'][k]['contextPath'] + ' | '
                    commands_string += str(integration['script']['commands'][i]['outputs'][k].get('type', 'unknown')) + ' | '
                    if not (integration['script']['commands'][i]['outputs'][k].get('description', False)):
                        return_error("Error! You are missing description in output {} of command {}"
                                     .format(integration['script']['commands'][i]['outputs'][j]['name'],
                                             integration['script']['commands'][i]['name']))
                        sys.exit(0)

                    commands_string += integration['script']['commands'][i]['outputs'][k]['description'] + ' | \n'
            else:
                commands_string += 'There is no context output for this command.\n'

            # Raw output:
            commands_string += '##### Command Example\n'
            commands_string += '##### Context Example\n'
            commands_string += '##### Human Readable Output\n'
            commands_string += '\n'
        except Exception as e:
            return_error("Error encountered in the processing of command {} error was missing a {}. "
                         "Please check your command inputs and outputs".format(integration['script']['commands'][i]['name'], str(e)))
            sys.exit(0)

    return commands_string


# load the integration yml file
if len(sys.argv) < 2:
    print("You must provide full path of integration yml file")
    exit(1)

path = sys.argv[1]
yaml_file = open(path)
data_map = yaml.safe_load(yaml_file)
yaml_file.close()

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

doc += get_list_of_commands(data_map)
doc += get_all_commands_details_string(data_map)

# Additional info
doc += '\n## Additional information:\n'

# Known limitations
doc += '\n## Known limitations:'

# Troubleshooting
doc += '\n## Troubleshooting:\n'

filename = os.path.basename(sys.argv[1]).replace('documentation-', 'integration-').replace('.yml', '.txt').replace('.yaml', '.txt')  # strip all the spaces
save_path = filename

# save file by default at same path unless the second arg provided
if len(sys.argv) > 2:
    save_path = sys.argv[2]
    if not os.path.isdir(save_path):
        return_error('{} is invalid folder'.format(save_path))

    save_path = os.path.join(save_path, filename)

with open(save_path, 'w') as f:
    f.write(doc)

print("Integration documentation file generated at: \n" + save_path)