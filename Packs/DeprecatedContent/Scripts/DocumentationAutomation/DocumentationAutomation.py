import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import yaml  # type: ignore
import sys

reload(sys)
sys.setdefaultencoding('utf-8')  # pylint: disable=E1101
CMD_ARGS_REGEX = re.compile(r'([\w_-]+)=((\"[^"]+\")|(`.+`)|(\"\"\".+\"\"\")|([^ ]+)) ?', re.S)


def get_yaml_obj(entry_id):
    data = {}  # type: dict
    try:
        yml_file_path = demisto.getFilePath(entry_id)['path']
        with open(yml_file_path, 'r') as yml_file:
            data = yaml.safe_load(yml_file)
        if not isinstance(data, dict):
            raise ValueError()

    except (ValueError, yaml.YAMLError):
        return_error('Failed to open integration file')

    return data


def get_command_examples(entry_id):
    """
    get command examples from command file

    @param entry_id: an entry ID of a command file or the content of such file

    @return: a list of command examples
    """
    commands = []  # type: list
    errors = []  # type: list
    if entry_id is None:
        return commands, errors

    if re.match(r'[\d]+@[\d\w-]+', entry_id) is not None:
        examples_path = demisto.getFilePath(entry_id)['path']
        with open(examples_path, 'r') as examples_file:
            commands = examples_file.read().split('\n')
    else:
        demisto.debug('failed to open command file, tried parsing as free text')
        commands = entry_id.split('\n')

    demisto.debug('found the following commands:\n{}'.format('\n* '.join(commands)))
    return commands, errors


def build_example_dict(command_examples):
    """
    gets an array of command examples, run them one by one and return a map of
        {base command -> (example command, markdown, outputs)}
    Note: if a command appears more then once, run all occurrences but stores only the first.
    """
    examples = {}  # type: dict
    errors = []  # type: list
    for example in command_examples:
        if example.startswith('!'):
            cmd, md_example, context_example, cmd_errors = run_command(example[1:])
            errors.extend(cmd_errors)

            if cmd not in examples:
                examples[cmd] = (example, md_example, context_example)

    return examples, errors


def extract_command(cmd_example):
    cmd = cmd_example
    args = dict()  # type: dict
    if ' ' in cmd_example:
        cmd, args_str = cmd_example.split(' ', 1)
        args = dict([(k, v.strip('"`')) for k, v, _, _, _, _ in CMD_ARGS_REGEX.findall(args_str)])

    return cmd, args


def run_command(command_example):
    errors = []
    context_example = ''
    md_example = ''
    cmd = command_example
    try:
        cmd, kwargs = extract_command(command_example)
        res = demisto.executeCommand(cmd, kwargs)

        for entry in res:
            if is_error(entry):
                demisto.results(res)
                raise RuntimeError('something went wrong with your command: {}'.format(command_example))

            raw_context = entry.get('EntryContext', {})
            if raw_context is not None:
                context = {k.split('(')[0]: v for k, v in raw_context.items()}
                context_example += json.dumps(context, indent=4)
            if entry.get('HumanReadable') is None:
                if entry.get('Contents') is not None:
                    content = entry.get('Contents')
                    if isinstance(content, STRING_TYPES):
                        md_example += content
                    else:
                        md_example += json.dumps(content)
            else:
                md_example += entry.get('HumanReadable')

    except RuntimeError:
        errors.append('The provided example for cmd {} has failed...'.format(cmd))

    except Exception as e:
        errors.append(
            'Error encountered in the processing of command {}, error was: {}. '.format(cmd, str(e))
            + '. Please check your command inputs and outputs')

    return cmd, md_example, context_example, errors


def add_lines(line):
    output = re.findall(r'^\d+\..+', line, re.MULTILINE)
    return output if output else [line]


def addErrorLines(scriptToScan, scriptType):
    res = ''
    if 'python' in scriptType:
        errorKeys = ['return_error', 'raise ']
    elif 'javascript' in scriptType:
        errorKeys = ['throw ']
    # Unsupported script type
    else:
        return res
    linesToSkip = 0
    scriptLines = scriptToScan.splitlines()
    for idx in range(len(scriptLines)):
        # Skip lines that were already scanned
        if linesToSkip > 0:
            linesToSkip -= 1
            continue
        line = scriptLines[idx]
        if any(key in line for key in errorKeys):
            if '(' in line:
                bracketOpenIdx = line.index('(') + 1
                if ')' in line:
                    bracketCloseIdx = line.index(')')
                    res += '* ' + line[bracketOpenIdx:bracketCloseIdx] + '\n'
                # Handle multi line error
                else:
                    res += '*' + ('' if len(line[bracketOpenIdx:].lstrip()) < 1 else ' ' + line[bracketOpenIdx:] + '\n')
                    while ')' not in scriptLines[idx + linesToSkip + 1]:
                        linesToSkip += 1
                        line = scriptLines[idx + linesToSkip]
                        res += ' ' + line.lstrip() + '\n'
                    # Adding last line of error
                    linesToSkip += 1
                    line = scriptLines[idx + linesToSkip]
                    bracketCloseIdx = line.index(')')
                    res += line[:bracketCloseIdx].lstrip() + '\n'
            else:
                firstMatchingErrorKey = next((key for key in errorKeys if key in line), False)
                afterErrorKeyIdx = line.index(firstMatchingErrorKey) + len(firstMatchingErrorKey)  # type: ignore
                res += '* ' + line[afterErrorKeyIdx:] + '\n'
    return res


def generate_section(title, data):
    section = [
        '## {}'.format(title),
        '---',
        '',
    ]

    if data is not None:
        section.extend(add_lines(data))

    return section


# Setup integration on Demisto
def generate_setup_section(yaml_data):
    section = [
        '1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.',
        '2. Search for {}.'.format(yaml_data['name']),
        '3. Click __Add instance__ to create and configure a new integration instance.',
        '    * __Name__: a textual name for the integration instance.',
    ]
    for conf in yaml_data['configuration']:
        if conf['display']:
            section.append('    * __{}__'.format(conf['display']))
        else:
            section.append('    * __{}__'.format(conf['name']))
    section.append('4. Click __Test__ to validate the URLs, token, and connection.')

    return section


# Commands
def generate_commands_section(yaml_data, example_dict):
    errors = []  # type: list
    section = [
        '## Commands',
        '---',
        'You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.',
        'After you successfully execute a command, a DBot message appears in the War Room with the command details.'
    ]
    commands = filter(lambda cmd: not cmd.get('deprecated', False), yaml_data['script']['commands'])
    command_list = ['{}. {}'.format(i + 1, cmd['name']) for i, cmd in enumerate(commands)]
    section.extend(command_list)

    for i, cmd in enumerate(commands):
        cmd_section, cmd_errors = generate_single_command_section(i, cmd, example_dict)
        section.extend(cmd_section)
        errors.extend(cmd_errors)

    return section, errors


def generate_single_command_section(index, cmd, example_dict):
    cmd_example = example_dict.get(cmd['name'])
    errors = []
    section = [
        '### {}. {}'.format(index + 1, cmd['name']),
        '---',
        cmd.get('description', ' '),
        '##### Required Permissions',
        '**FILL IN REQUIRED PERMISSIONS HERE**',
        '##### Base Command',
        '',
        '`{}`'.format(cmd['name']),
        '##### Input',
        '',
    ]

    # Inputs
    arguments = cmd.get('arguments')
    if arguments is None:
        section.append('There are no input arguments for this command.')
    else:
        section.extend([
            '| **Argument Name** | **Description** | **Required** |',
            '| --- | --- | --- |',
        ])
        for arg in arguments:
            if not arg.get('description'):
                errors.append(
                    'Error! You are missing description in input {} of command {}'.format(arg['name'], cmd['name']))
            required_status = 'Required' if arg.get('required') else 'Optional'
            section.append('| {} | {} | {} | '.format(arg['name'], stringEscapeMD(arg.get('description', ''), True, True),
                                                      required_status))
        section.append('')

    # Context output
    section.extend([
        '',
        '##### Context Output',
        '',
    ])
    outputs = cmd.get('outputs')
    if outputs is None:
        section.append('There is no context output for this command.')
    else:
        section.extend([
            '| **Path** | **Type** | **Description** |',
            '| --- | --- | --- |'
        ])
        for output in outputs:
            if not output.get('description'):
                errors.append(
                    'Error! You are missing description in output {} of command {}'.format(output['contextPath'],
                                                                                           cmd['name']))
            section.append(
                '| {} | {} | {} | '.format(output['contextPath'], output.get('type', 'unknown'),
                                           output.get('description').encode('utf-8')))
        section.append('')

    # Raw output:
    example_section, example_errors = generate_command_example(cmd, cmd_example)
    section.extend(example_section)
    errors.extend(example_errors)

    return section, errors


def generate_command_example(cmd, cmd_example=None):
    errors = []
    context_example = None
    md_example = ''
    if cmd_example is not None:
        cmd_example, md_example, context_example = cmd_example
    else:
        cmd_example = ' '
        errors.append('did not get any example for {}. please add it manually.'.format(cmd['name']))

    example = [
        '',
        '##### Command Example',
        '```{}```'.format(cmd_example),
        '',
    ]
    if context_example:
        example.extend([
            '##### Context Example',
            '```',
            '{}'.format(context_example),
            '```',
            '',
        ])
    example.extend([
        '##### Human Readable Output',
        '{}'.format(md_example),
        '',
    ])

    return example, errors


def main():
    args = demisto.args()
    yml_data = get_yaml_obj(args['entryID'])
    command_examples, errors = get_command_examples(args.get('commands'))
    example_dict, build_errors = build_example_dict(command_examples)
    errors.extend(build_errors)

    docs = []  # type: list
    docs.extend(generate_section('Overview', args.get('overview', yml_data.get('description'))))
    docs.append('This integration was integrated and tested with version xx of {}'.format(yml_data['name']))
    # Playbooks
    docs.extend(generate_section('{} Playbook'.format(yml_data['name']), None))
    # Use-cases
    docs.extend(generate_section('Use Cases', args.get('useCases')))
    # Setup integration to work with Demisto
    docs.extend(generate_section('Configure {} on Demisto'.format(yml_data['name']), args.get('setupOnIntegration')))
    # Setup integration on Demisto
    docs.extend(generate_setup_section(yml_data))
    # Fetched incidents data
    docs.extend(generate_section('Fetched Incidents Data', args.get('fetchedData')))
    # Commands
    command_section, command_errors = generate_commands_section(yml_data, example_dict)
    docs.extend(command_section)
    errors.extend(command_errors)
    # Additional info
    docs.extend(generate_section('Additional Information', args.get('addInfo')))
    # Known limitations
    docs.extend(generate_section('Known Limitations', args.get('limit')))
    # Troubleshooting
    docs.extend(generate_section('Troubleshooting', args.get('troubleshooting')))
    # Possible Errors

    if args.get('withErrors', 'True') == 'True':
        docs.extend([
            '',
            '## Possible Errors (DO NOT PUBLISH ON ZENDESK):',
        ])
        docs.append(addErrorLines(yml_data['script']['script'], yml_data['script']['type']))

    documentation_text = '\n'.join(docs)
    filename = '{}-documentation.txt'.format(yml_data['name'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': documentation_text,
        'HumanReadable': documentation_text,
    })
    demisto.results(fileResult(filename, documentation_text, file_type=entryTypes['entryInfoFile']))
    if len(errors) != 0:
        errors.append('Visit the documentation page for more details: '
                      'https://github.com/demisto/content/tree/master/docs/integration_documentation')
        return_error('\n'.join('* {}'.format(e) for e in errors))


if __name__ == '__builtin__':
    main()
