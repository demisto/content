import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import yaml
from CommonServerUserPython import *

CMD_ARGS_REGEX = re.compile(r'([\w_-]+)=((?:\"[^"]+\")|(?:`.+`)|(?:\"\"\".+\"\"\")|(?:[^ ]+)) ?', re.S)

"""STRING TEMPLATES"""
OVERVIEW: str = '''<p>
{overview}
</p>
'''

SETUP_CONFIGURATION: str = '''<h2>Configure {integration_name} on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for {integration_name}.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
{params_list}
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
'''

PARAMS_LIST: str = '   <li><strong>{param}</strong></li>'

COMMANDS_HEADER: str = '''<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
{command_list}
</ol>
'''

PERMISSIONS_HEADER: str = '''<h2>Permissions</h2>
<p>The following permissions are required for all commands.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>'''

COMMAND_LIST: str = '  <li><a href="#{command}" target="_self">{command_hr}: {command}</a></li>'

PERMISSIONS_PER_COMMAND: str = '''
<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>'''

SINGLE_COMMAND: str = '''<h3 id="{command_hr}">{index}. {command_hr}</h3>
<hr>
<p>{command_description}</p>
<h5>Base Command</h5>
<p>
  <code>{command}</code>
</p>
{permissions}
<h5>Input</h5>
{arg_table}
<p>&nbsp;</p>
<h5>Context Output</h5>
{context_table}
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>{command_example}</code>
</p>
{context_example}
<h5>Human Readable Output</h5>
<p>
{hr_example}
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
'''

CONTEXT_EXAMPLE: str = '''<h5>Context Example</h5>
<pre>
{context}
</pre>'''

ARG_TABLE: str = '''<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
{records}
  </tbody>
</table>
'''

ARG_RECORD: str = '''    <tr>
      <td>{name}</td>
      <td>{description}</td>
      <td>{required}</td>
    </tr>'''

CONTEXT_TABLE: str = '''<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
{records}
  </tbody>
</table>
'''

CONTEXT_RECORD: str = '''    <tr>
      <td>{path}</td>
      <td>{type}</td>
      <td>{description}</td>
    </tr>'''

HTML_GENERIC_TABLE: str = '''<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
{headers}
    </tr>
  </thead>
  <tbody>
{records}
  </tbody>
</table>
'''

GENERIC_HEADER: str = '      <th><strong>{}</strong></th>'

GENERIC_RECORD: str = '''    <tr>
{data_fields}
    </tr>'''


def get_yaml_obj(entry_id):
    data = {}  # type: dict
    try:
        yml_file_path = demisto.getFilePath(entry_id)['path']
        with open(yml_file_path, 'r') as yml_file:
            data = yaml.safe_load(yml_file)
        if not isinstance(data, dict):
            raise ValueError('not a yml file')

    except (ValueError, yaml.YAMLError) as exception:
        return_error('Failed to open integration file: {}'.format(exception))

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
        args = {k: v.strip('"`') for k, v in CMD_ARGS_REGEX.findall(args_str)}

    return cmd, args


def run_command(command_example):
    errors: list = []
    context_example: str = ''
    md_example: str = ''
    cmd, kwargs = extract_command(command_example)
    try:
        res = demisto.executeCommand(cmd, kwargs)
        if is_error(res):
            demisto.results(res)
            raise RuntimeError()

    except (ValueError, RuntimeError) as exception:
        errors.append(
            'Error encountered in the processing of command `{}`, error was: {}. '.format(command_example,
                                                                                          str(exception))
            + 'Please check your command inputs and outputs.')
        # errors.append('The provided example for cmd {} has failed: {}'.format(cmd, str(exception)))

    else:
        for entry in res:
            raw_context = entry.get('EntryContext', {})
            if raw_context is not None:
                context = {k.split('(')[0]: v for k, v in raw_context.items()}
                context_example += json.dumps(context, indent=4)
            if entry.get('HumanReadable') is None:
                content = entry.get('Contents')
                if content:
                    if isinstance(content, str):
                        md_example += content
                    elif isinstance(content, bytes):
                        md_example += content.decode('utf-8')
                    else:
                        md_example += json.dumps(content)
            else:
                md_example += entry.get('HumanReadable')

    return cmd, md_example, context_example, errors


def to_html_table(headers: list, data: list):
    records: list = []
    for data_record in data:
        records.append(GENERIC_RECORD.format(data_fields='\n'.join('      <td>{}</td>'.format(field)
                                                                   for field in data_record)))

    return HTML_GENERIC_TABLE.format(headers='\n'.join(GENERIC_HEADER.format(h) for h in headers),
                                     records='\n'.join(records))


def human_readable_example_to_html(hr_sample):
    table_regex = re.compile(r'(\|(.*\|)+\s\|(?:---\|)+\s((?:\|(?:.*\|)+\s?)+))')
    hr_html: list = []
    while hr_sample:
        if hr_sample.startswith('#'):
            title = hr_sample
            if '\n' in hr_sample:
                title, hr_sample = hr_sample.split('\n', 1)
            else:
                hr_sample = ''
            heading_size = len(title) - len(title.lstrip('#'))
            hr_html.append('<h{0}>{1}</h{0}>'.format(heading_size, title[heading_size + 1:]))
            continue

        table = table_regex.match(hr_sample)
        if table:
            headers = table.group(2).split('|')[:-1]
            data = [fields.split('|')[1:-1]
                    for fields in table.group(3).strip().split('\n')]
            hr_html.append(to_html_table(headers, data))
            truncate = len(table.group(0))
            hr_sample = hr_sample[truncate:]
            continue

        paragraph: list = []
        while hr_sample and not hr_sample.startswith('#') and not hr_sample.startswith('|'):
            if '\n' in hr_sample:
                paragraph_line, hr_sample = hr_sample.split('\n', 1)
            else:
                paragraph_line, hr_sample = hr_sample, ''

            if paragraph_line:
                paragraph.append(paragraph_line)
        if paragraph:
            hr_html.append('<p>\n{}\n</p>'.format('\n'.join(paragraph)))

    return '\n'.join(hr_html)


def generate_use_case_section(title, data):
    html_section = [
        '<h2>{}</h2>'.format(title),
    ]

    if not data:
        data = ''

    if os.linesep in data:
        html_section.append('<ul>')
        html_section.extend('<li>{}</li>'.format(s) for s in data.split(os.linesep))
        html_section.append('</ul>')
    else:
        html_section.append('<p>{}</p>'.format(data))

    return html_section


def generate_section(title, data):
    html_section = [
        '<h2>{}</h2>'.format(title),
    ]

    if data:
        if '\n' in data:
            html_section.append('<ul>')
            html_section.extend('<li>{}</li>'.format(s) for s in data.split('\n'))
            html_section.append('</ul>')
        else:
            html_section.append('<p>{}</p>\n'.format(data))

    return '\n'.join(html_section)


# Setup integration on Demisto
def generate_setup_section(yaml_data):
    params_list = [
        PARAMS_LIST.format(param=conf['display'] if conf.get('display') else conf['name']) for
        conf in yaml_data.get('configuration', [])]
    return SETUP_CONFIGURATION.format(params_list='\n'.join(params_list), integration_name=yaml_data['name'])


# Commands
def generate_commands_section(yaml_data, example_dict, should_include_permissions):
    errors: list = []
    command_sections: list = []

    commands = [cmd for cmd in yaml_data['script']['commands'] if not cmd.get('deprecated')]
    command_list = [COMMAND_LIST.format(command_hr=cmd['description'].rstrip('.'), command=cmd['name'])
                    for cmd in commands]

    for i, cmd in enumerate(commands):
        cmd_section, cmd_errors = generate_single_command_section(i + 1, cmd, example_dict, should_include_permissions)
        command_sections.append(cmd_section)
        errors.extend(cmd_errors)

    return (COMMANDS_HEADER.format(command_list='\n'.join(command_list)) + '\n'.join(command_sections)), errors


def generate_single_command_section(index, cmd, example_dict, should_include_permissions):
    cmd_example: str = example_dict.get(cmd['name'])
    errors: list = []
    template: dict = {
        'index': index,
        'command_hr': cmd['name'],
        'command': cmd['name'],
        'command_description': cmd.get('description', ' '),
        'permissions': PERMISSIONS_PER_COMMAND if should_include_permissions else '',
    }

    # Inputs
    arguments: list = cmd.get('arguments')
    if arguments is None:
        template['arg_table'] = 'There are no input arguments for this command.'
    else:
        arg_table: list = []
        for arg in arguments:
            if not arg.get('description'):
                errors.append(
                    'Error! You are missing description in input {} of command {}'.format(arg['name'], cmd['name']))
            required_status = 'Required' if arg.get('required') else 'Optional'
            arg_table.append(ARG_RECORD.format(name=arg['name'],
                                               description=arg.get('description'),
                                               required=required_status))
        template['arg_table'] = ARG_TABLE.format(records='\n'.join(arg_table))

    # Context output
    outputs: list = cmd.get('outputs')
    if outputs is None:
        template['context_table'] = 'There are no context output for this command.'
    else:
        context_table: list = []
        for output in outputs:
            if not output.get('description'):
                errors.append(
                    'Error! You are missing description in output {} of command {}'.format(output['contextPath'],
                                                                                           cmd['name']))
            context_table.append(CONTEXT_RECORD.format(path=output['contextPath'],
                                                       type=output.get('type', 'unknown'),
                                                       description=output.get('description')))
        template['context_table'] = CONTEXT_TABLE.format(records='\n'.join(context_table))

    # Raw output:
    example_template, example_errors = generate_command_example(cmd, cmd_example)
    template.update(example_template)
    errors.extend(example_errors)

    return SINGLE_COMMAND.format(**template), errors


def generate_command_example(cmd, cmd_example=None):
    errors: list = []
    context_example = None
    md_example: str = ''
    if cmd_example:
        cmd_example, md_example, context_example = cmd_example
    else:
        cmd_example = ' '
        errors.append('did not get any example for {}. please add it manually.'.format(cmd['name']))

    example = {
        'command_example': cmd_example,
        'hr_example': human_readable_example_to_html(md_example),
        'context_example': CONTEXT_EXAMPLE.format(context=context_example) if context_example else '',
    }

    return example, errors


def generate_html_docs(args, yml_data, example_dict, errors):
    docs: str = ''
    # Overview
    overview = (args.get('overview', yml_data.get('description'))
                + '\n\nThis integration was integrated and tested with version xx of {}'.format(yml_data['name']))
    docs += OVERVIEW.format(overview=overview)

    # Playbooks
    docs += generate_section('{} Playbook'.format(yml_data['name']),
                             'Populate this section with relevant playbook names.')

    # Use Cases
    docs += generate_section('Use Cases',
                             args.get('useCases', 'Use case 1\nUse case 2'))

    # Detailed Descriptions
    docs += generate_section('Detailed Description',
                             yml_data.get('detaileddescription',
                                          'Populate this section with the .md file contents for detailed description.'))
    # Fetch Data
    docs += generate_section('Fetch Incidents',
                             args.get('fetchedData',
                                      'Populate this section with Fetch incidents data'))

    # # Setup integration to work with Demisto
    # docs.extend(generate_section('Configure {} on Demisto'.format(yml_data['name']), args.get('setupOnIntegration')))

    # Setup integration on Demisto
    docs += (generate_setup_section(yml_data))

    #  Permissions
    if args.get('permissions') == 'global':
        docs += PERMISSIONS_HEADER

    # Commands
    command_section, command_errors = generate_commands_section(yml_data, example_dict,
                                                                args.get('permissions') == 'per-command')
    docs += command_section
    errors.extend(command_errors)

    # Additional info
    docs += generate_section('Additional Information', args.get('addInfo'))

    # Known limitations
    docs += generate_section('Known Limitations', args.get('limit'))

    # Troubleshooting
    docs += generate_section('Troubleshooting', args.get('troubleshooting'))

    return docs


def main():
    args: dict = demisto.args()
    yml_data: dict = get_yaml_obj(args.get('entryID'))
    command_examples, errors = get_command_examples(args.get('commands'))
    example_dict, build_errors = build_example_dict(command_examples)
    errors.extend(build_errors)

    docs: str = generate_html_docs(args, yml_data, example_dict, errors)

    filename = '{}-documentation.html'.format(yml_data['name'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['html'],
        'Contents': docs,
        # 'HumanReadable': docs,
    })
    demisto.results(fileResult(filename, docs, file_type=entryTypes['entryInfoFile']))
    if errors:
        errors.append('Visit the documentation page for more details: '
                      'https://github.com/demisto/content/tree/master/docs/integration_documentation')
        return_error('\n'.join('* {}'.format(e) for e in errors))


if __name__ == 'builtins':
    main()
