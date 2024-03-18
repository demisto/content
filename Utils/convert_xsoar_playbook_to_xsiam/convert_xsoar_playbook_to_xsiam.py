import io
import os
from pathlib import Path
from typing import List
import yaml

import click
from demisto_sdk.commands.common.content_constant_paths import CONTENT_PATH
from demisto_sdk.commands.common.logger import logging_setup
import logging as logger
import typer
from demisto_sdk.commands.content_graph.objects.base_content import BaseContent

import json

playbook_converer_app = typer.Typer(name="Playbook-Converter")

CORE_ALERT_FIELDS_PATH = 'Utils/convert_xsoar_playbook_to_xsiam/system_fields.json'

def util_load_json(path):
    """
    Loads JSON data from a file path into a usable data structure.
    """
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())

def get_system_alert_fields():
    """
    Retrieves system alerts.
    """
    try:
        with open(CORE_ALERT_FIELDS_PATH, 'r') as file:
            return json.load(file)
    except:
        logger.warning("The list of system alert fields is empty.")
        return {}


@click.group(
    invoke_without_command=True,
    no_args_is_help=True,
    context_settings=dict(max_content_width=100),
)
@click.help_option("-h", "--help")
def main():
    logging_setup(logger.DEBUG)

def replace_occurrences(data, replace_from, replace_to, mapping):
    """
    Searches for and replaces specific substrings within the data.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str) and replace_from in value:
                if f"{replace_from}.Alert" in value:
                    field = value.split('.')[-1]
                    field_mapping = mapping.get(field)
                    data[key] = value.replace(f"{replace_from}.Alert.{field}", f"Alert.{field_mapping}") if field_mapping else value.replace(f"{keyword}.Alert", "Alert")
                else:
                    data[key] = value.replace(replace_from, replace_to)

            elif isinstance(value, (dict, list)):
                replace_occurrences(value, replace_from, replace_to, mapping)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, str) and replace_from in item:
                data[i] = item.replace(replace_from, mapping)
            elif isinstance(item, (dict, list)):
                replace_occurrences(item, replace_from, replace_to, mapping)


@playbook_converer_app.command()
def convert_playbook(
    input_path: str = typer.Option(None, "--input", "-i", help="The path to the playbook yaml file."),
    output: str = typer.Option(None, "--output", "-o", help="The path to save the converted playbook yaml file."),
    ):
    """Converts XDR playbooks from one format to another."""
    # Currently supports only conversion from XSOAR to XSIAM
    commands_not_replaced_str = ""
    mapping = util_load_json('Utils/convert_xsoar_playbook_to_xsiam/xsoar_to_xsiam_command_mapping.json')

    system_alert_fields = get_system_alert_fields()
    playbook_path = CONTENT_PATH / Path(input_path)

    playbook = BaseContent.from_path(playbook_path)
    commands_replaced = {}
    commands_not_replaced = []
    if playbook_name := playbook.name:
        playbook.name = f'{playbook_name} Converted'
    if playbook_id := playbook.object_id:
        playbook.object_id = f'{playbook_id} Converted'
    if playbook_display_name := playbook.display_name:
        playbook.display_name = f'{playbook_display_name} Converted'

    # iterates on playbook tasks to replace command names (xdr-some-command -> core-some-command).
    for id, data in playbook.tasks.items():

        if (task_script_name := data.task.script) and (coammnd_name := task_script_name.replace('|','')) in mapping:
            if convert_to := mapping[coammnd_name]:
                data.task.script = f'|||{convert_to}'
                commands_replaced[coammnd_name] = convert_to
                task_name = data.task.name
                if 'xdr' in task_name:
                    data.task.name = task_name.replace('xdr', 'core')
            else:
                commands_not_replaced.append(coammnd_name)

    output_path = Path(f"{output}/{playbook.path.stem}_converted.yml") if output else Path(f"{playbook_path.parent}/{playbook.path.stem}_converted.yml")

    playbook.save(output_path)
    with open(output_path, 'r') as file:
        yaml_data = yaml.safe_load(file)

    # Replaces outputs/inputs XDR occurrences with Core
    replace_occurrences(yaml_data, "PaloAltoNetworksXDR", 'Core', system_alert_fields)
    with open(output_path, 'w') as file:
        yaml.dump(yaml_data, file)

    commands_replaced_str = f"Converted the following commands:\n"
    commands_replaced_str += "\n".join(f'{k} --> {v}' for k,v in commands_replaced.items())
    if commands_not_replaced:
        commands_not_replaced_str = f"\nDid not manage to Convert the following commands (please change them manually):\n"
        commands_not_replaced_str += "\n".join(commands_not_replaced)
    logger.warning(commands_replaced_str)
    logger.warning(commands_not_replaced_str)

main.add_command(typer.main.get_command(playbook_converer_app), "convert-playbook")



if __name__ == "__main__":
    main()


